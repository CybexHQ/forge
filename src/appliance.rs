//! Ubuntu appliance state and health projection.

use anyhow::{Context, Result, anyhow, bail};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Read, Write},
    os::unix::fs::PermissionsExt,
    path::{Component, Path, PathBuf},
};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

pub const APPLIANCE_UPDATE_CAPABILITY: &str = "appliance_update_v1";
const RELEASE_PATH: &str = "/usr/share/cybex-forge/appliance-release.json";
const INSTALLED_STATE_PATH: &str = "/var/lib/cybex-forge/state/appliance-release.json";
const UPDATE_STATUS_PATH: &str = "/var/lib/cybex-forge/state/appliance-update-status.json";
const UPDATE_REQUEST_PATH: &str = "/var/lib/cybex-forge/state/appliance-update-request.json";
const UPDATE_BUNDLE_ROOT: &str = "/var/lib/cybex-forge/state/appliance-update-bundles";
const UPDATE_ROOT: &str = "/var/lib/cybex-forge/state/appliance-updates";
const RELEASE_PUBLIC_KEY_PATH: &str = "/usr/share/cybex-forge/release-public-key";
const PROVISIONING_STATE_PATH: &str = "/var/lib/cybex-forge/state/provisioning-state.json";
const INSTALL_PLAN_PATH: &str = "/var/lib/cybex-forge/state/install-plan.json";
const NETWORK_CHANGE_REQUEST_PATH: &str =
    "/var/lib/cybex-forge/state/appliance-network-change-request.json";
const NETWORK_CHANGE_STATUS_PATH: &str =
    "/var/lib/cybex-forge/state/appliance-network-change-status.json";
const NETWORK_PENDING_PATH: &str = "/var/lib/cybex-forge/state/netplan-pending.sha256";
const NETWORK_ACK_PATH: &str = "/var/lib/cybex-forge/state/netplan-ack.sha256";
const APPLIANCE_RELEASE_SIGNATURE_DOMAIN: &str = "CYBEX-FORGE-APPLIANCE-RELEASE-V1";
const APPLIANCE_RELEASE_SCHEMA: &str = "cybex.forge.appliance-release.v1";
const NETWORK_CHANGE_SIGNATURE_DOMAIN: &str = "CYBEX-FORGE-NETWORK-CHANGE-V1";
const NETWORK_ACK_SIGNATURE_DOMAIN: &str = "CYBEX-FORGE-NETWORK-ACK-V1";
const MAX_UPDATE_BUNDLE_BYTES: u64 = 16 * 1024 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApplianceRelease {
    schema: String,
    release_id: String,
    ubuntu_snapshot_id: String,
    root_generation: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApplianceRepositorySnapshot {
    pub url: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedApplianceRelease {
    pub schema: String,
    pub release_id: String,
    pub ubuntu_snapshot_id: String,
    pub cybex_repository_snapshot: ApplianceRepositorySnapshot,
    pub required_package_versions: BTreeMap<String, String>,
    pub expected_kernel: String,
    pub minimum_protocol: u32,
    pub minimum_state_schema: u32,
    pub rollback_compatible: bool,
    pub release_notes: String,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedApplianceUpdate {
    pub attempt_id: uuid::Uuid,
    pub requested_at: DateTime<Utc>,
    pub release: SignedApplianceRelease,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredApplianceUpdate {
    schema: String,
    attempt_id: uuid::Uuid,
    requested_at: DateTime<Utc>,
    release: SignedApplianceRelease,
    bundle_path: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApplianceNetworkInput {
    pub mode: String,
    pub interface_id: String,
    pub address_cidr: Option<String>,
    pub gateway: Option<String>,
    #[serde(default)]
    pub dns_servers: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedApplianceNetworkChange {
    pub schema: String,
    pub id: uuid::Uuid,
    pub device_id: String,
    pub device_incarnation_id: uuid::Uuid,
    pub revision: i64,
    pub network: ApplianceNetworkInput,
    pub config_sha256: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedApplianceNetworkAcknowledgement {
    pub schema: String,
    pub change_id: uuid::Uuid,
    pub device_id: String,
    pub candidate_sha256: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub signature: String,
}

#[derive(Clone, Debug)]
pub struct PendingApplianceNetworkAcknowledgement {
    pub change_id: uuid::Uuid,
    pub candidate_sha256: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ApplianceReport {
    pub base_os: String,
    pub base_os_version: String,
    pub appliance_release: String,
    pub ubuntu_snapshot_id: String,
    pub root_generation: String,
    pub kernel_version: String,
    pub secure_boot: bool,
    pub boot_mode: String,
    pub firmware_version: String,
    pub microcode_version: String,
    pub nix_version: String,
    pub at_rest_protection: String,
    pub network: Value,
    pub package_update: Value,
    pub local_health: Value,
}

pub fn is_managed_ubuntu() -> bool {
    Path::new(RELEASE_PATH).is_file() && Path::new(INSTALLED_STATE_PATH).is_file()
}

pub async fn store_update_request(update: Option<ManagedApplianceUpdate>) -> Result<()> {
    let Some(update) = update else {
        return Ok(());
    };
    if !is_managed_ubuntu() {
        bail!("received an Ubuntu appliance update on a non-appliance Forge host")
    }
    validate_managed_update(&update)?;
    if read_optional_bounded_json::<Value>(Path::new(UPDATE_STATUS_PATH), 128 * 1024).is_some_and(
        |status| {
            status.get("attempt_id").and_then(Value::as_str)
                == Some(update.attempt_id.to_string().as_str())
                && matches!(
                    status.get("status").and_then(Value::as_str),
                    Some("succeeded" | "rolled_back" | "failed")
                )
        },
    ) {
        return Ok(());
    }
    if let Some(existing) = read_optional_bounded_json::<StoredApplianceUpdate>(
        Path::new(UPDATE_REQUEST_PATH),
        256 * 1024,
    ) {
        if existing.attempt_id == update.attempt_id
            && existing.release.signature == update.release.signature
        {
            return Ok(());
        }
        bail!("another Ubuntu appliance update request is already durable")
    }

    tokio::fs::create_dir_all(UPDATE_BUNDLE_ROOT)
        .await
        .context("create appliance update bundle directory")?;
    let bundle_path = Path::new(UPDATE_BUNDLE_ROOT).join(format!("{}.tar.zst", update.attempt_id));
    download_snapshot(&update.release.cybex_repository_snapshot, &bundle_path).await?;
    let stored = StoredApplianceUpdate {
        schema: "cybex.forge.appliance-update-request.v1".to_string(),
        attempt_id: update.attempt_id,
        requested_at: update.requested_at,
        release: update.release,
        bundle_path: bundle_path
            .to_str()
            .ok_or_else(|| anyhow!("appliance update bundle path is invalid"))?
            .to_string(),
    };
    write_atomic_json(Path::new(UPDATE_REQUEST_PATH), &stored, 0o600)?;
    write_atomic_json(
        Path::new(UPDATE_STATUS_PATH),
        &json!({
            "status": "waiting_window",
            "stage": "downloaded",
            "attempt_id": stored.attempt_id,
            "target_release": stored.release.release_id,
            "progress_percent": 5,
            "candidate_root_generation": "",
            "resulting_root_generation": "",
            "rollback_reason": "",
            "reported_at": Utc::now(),
        }),
        0o600,
    )?;
    Ok(())
}

/// Re-verify the offline-signed descriptor and exact archive as root, then
/// extract the package snapshot into the root updater's private staging tree.
pub fn verify_and_extract_stored_update() -> Result<PathBuf> {
    let request: StoredApplianceUpdate =
        read_bounded_json(Path::new(UPDATE_REQUEST_PATH), 256 * 1024)?;
    if request.schema != "cybex.forge.appliance-update-request.v1" {
        bail!("stored appliance update request schema is unsupported")
    }
    validate_managed_update(&ManagedApplianceUpdate {
        attempt_id: request.attempt_id,
        requested_at: request.requested_at,
        release: request.release.clone(),
    })?;
    let expected_bundle =
        Path::new(UPDATE_BUNDLE_ROOT).join(format!("{}.tar.zst", request.attempt_id));
    if Path::new(&request.bundle_path) != expected_bundle {
        bail!("stored appliance update bundle path is not canonical")
    }
    let mut bundle = fs::File::open(&expected_bundle).context("open appliance update bundle")?;
    verify_bundle_reader(
        &mut bundle,
        request.release.cybex_repository_snapshot.size_bytes,
        &request.release.cybex_repository_snapshot.sha256,
    )?;

    fs::create_dir_all(UPDATE_ROOT).context("create appliance update root")?;
    let release_root = Path::new(UPDATE_ROOT).join(&request.release.release_id);
    let packages = release_root.join("packages");
    if packages.is_dir() {
        verify_extracted_snapshot(&packages, &request.release)?;
        return Ok(packages);
    }
    fs::create_dir(&release_root).context("create appliance release update directory")?;
    fs::set_permissions(&release_root, fs::Permissions::from_mode(0o700))?;
    let temporary = release_root.join(format!(".packages.{}", request.attempt_id));
    fs::create_dir(&temporary).context("create appliance package staging directory")?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o700))?;
    let extract_result = (|| -> Result<()> {
        use std::io::Seek;
        bundle.rewind().context("rewind appliance update bundle")?;
        extract_snapshot(&mut bundle, &temporary)?;
        verify_extracted_snapshot(&temporary, &request.release)?;
        for entry in fs::read_dir(&temporary)? {
            let path = entry?.path();
            fs::set_permissions(path, fs::Permissions::from_mode(0o444))?;
        }
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o555))?;
        fs::rename(&temporary, &packages).context("commit verified appliance package snapshot")?;
        sync_directory(&release_root)?;
        Ok(())
    })();
    if extract_result.is_err() {
        let _ = fs::remove_dir_all(&temporary);
    }
    extract_result?;
    Ok(packages)
}

fn validate_managed_update(update: &ManagedApplianceUpdate) -> Result<()> {
    if update.attempt_id.is_nil() {
        bail!("appliance update attempt ID is nil")
    }
    validate_signed_release(&update.release)?;
    let installed: ApplianceRelease = read_bounded_json(Path::new(RELEASE_PATH), 64 * 1024)?;
    let current = semver::Version::parse(&installed.release_id)
        .context("installed appliance release is not canonical SemVer")?;
    let target = semver::Version::parse(&update.release.release_id)
        .context("target appliance release is not canonical SemVer")?;
    if current.to_string() != installed.release_id
        || target.to_string() != update.release.release_id
        || !target.cmp_precedence(&current).is_gt()
    {
        bail!("appliance update release is not strictly newer than the installed release")
    }
    Ok(())
}

fn validate_signed_release(release: &SignedApplianceRelease) -> Result<()> {
    if release.schema != APPLIANCE_RELEASE_SCHEMA
        || release.minimum_protocol != 4
        || release.minimum_state_schema != 1
        || !release.rollback_compatible
        || !is_snapshot_id(&release.ubuntu_snapshot_id)
    {
        bail!("appliance release contract is incompatible")
    }
    let version = semver::Version::parse(&release.release_id)
        .context("appliance release ID is not SemVer")?;
    if version.to_string() != release.release_id {
        bail!("appliance release ID is not canonical SemVer")
    }
    let snapshot = &release.cybex_repository_snapshot;
    let url = Url::parse(&snapshot.url).context("parse appliance package snapshot URL")?;
    let expected_filename = format!(
        "cybex-forge-appliance-packages-{}-x86_64-linux.tar.zst",
        release.release_id
    );
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.query().is_some()
        || url
            .path_segments()
            .and_then(|mut segments| segments.next_back())
            != Some(expected_filename.as_str())
    {
        bail!("appliance package snapshot URL is not canonical HTTPS")
    }
    require_sha256(&snapshot.sha256)?;
    if snapshot.size_bytes == 0 || snapshot.size_bytes > MAX_UPDATE_BUNDLE_BYTES {
        bail!("appliance package snapshot size is invalid")
    }
    let expected_packages = BTreeSet::from([
        "cybex-forge".to_string(),
        "cybex-forge-appliance".to_string(),
        "cybex-forge-bootstrap".to_string(),
        "linux-firmware".to_string(),
        "linux-generic".to_string(),
        "nix-bin".to_string(),
    ]);
    if release
        .required_package_versions
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>()
        != expected_packages
        || release
            .required_package_versions
            .values()
            .any(|value| !is_safe_token(value, 256))
        || release.expected_kernel != release.required_package_versions["linux-generic"]
    {
        bail!("appliance required package versions are invalid")
    }
    let notes = Url::parse(&release.release_notes).context("parse appliance release notes URL")?;
    if notes.scheme() != "https"
        || notes.host_str().is_none()
        || !notes.username().is_empty()
        || notes.password().is_some()
        || notes.fragment().is_some()
    {
        bail!("appliance release notes URL is invalid")
    }

    let key_text =
        fs::read_to_string(RELEASE_PUBLIC_KEY_PATH).context("read appliance release public key")?;
    let key_bytes = canonical_base64(key_text.trim_end_matches('\n'), 32)?;
    if key_text != format!("{}\n", STANDARD.encode(&key_bytes)) {
        bail!("appliance release public key file is not canonical")
    }
    let verifying_key = VerifyingKey::from_bytes(
        key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("appliance release public key length is invalid"))?,
    )
    .context("parse appliance release public key")?;
    if verifying_key.is_weak() {
        bail!("appliance release public key is weak")
    }
    let signature = canonical_base64(&release.signature, 64)?;
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| anyhow!("appliance release signature length is invalid"))?;
    let mut unsigned = serde_json::to_value(release)?;
    unsigned
        .as_object_mut()
        .ok_or_else(|| anyhow!("appliance release descriptor is not an object"))?
        .remove("signature");
    let body = serde_json::to_vec(&canonical_json(unsigned))?;
    let mut payload = Vec::with_capacity(APPLIANCE_RELEASE_SIGNATURE_DOMAIN.len() + body.len() + 1);
    payload.extend_from_slice(APPLIANCE_RELEASE_SIGNATURE_DOMAIN.as_bytes());
    payload.push(b'\n');
    payload.extend_from_slice(&body);
    verifying_key
        .verify_strict(&payload, &Signature::from_bytes(&signature))
        .context("verify appliance release signature")
}

async fn download_snapshot(snapshot: &ApplianceRepositorySnapshot, target: &Path) -> Result<()> {
    if target.exists() {
        let mut existing = fs::File::open(target)?;
        return verify_bundle_reader(&mut existing, snapshot.size_bytes, &snapshot.sha256);
    }
    let temporary = target.with_extension(format!("tar.zst.part.{}", uuid::Uuid::new_v4()));
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(std::time::Duration::from_secs(15))
        .timeout(std::time::Duration::from_secs(4 * 60 * 60))
        .build()?;
    let mut response = client
        .get(&snapshot.url)
        .header(reqwest::header::ACCEPT_ENCODING, "identity")
        .send()
        .await
        .context("download appliance package snapshot")?;
    if !response.status().is_success()
        || response
            .content_length()
            .is_some_and(|length| length != snapshot.size_bytes)
    {
        bail!("appliance package snapshot response is invalid")
    }
    let mut file = tokio::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)
        .await?;
    let mut hasher = Sha256::new();
    let mut received = 0u64;
    let result = async {
        while let Some(chunk) = response.chunk().await? {
            received = received
                .checked_add(chunk.len() as u64)
                .ok_or_else(|| anyhow!("appliance package snapshot length overflow"))?;
            if received > snapshot.size_bytes {
                bail!("appliance package snapshot exceeded its signed size")
            }
            hasher.update(&chunk);
            file.write_all(&chunk).await?;
        }
        if received != snapshot.size_bytes || hex::encode(hasher.finalize()) != snapshot.sha256 {
            bail!("appliance package snapshot integrity check failed")
        }
        file.sync_all().await?;
        drop(file);
        tokio::fs::rename(&temporary, target).await?;
        Ok::<_, anyhow::Error>(())
    }
    .await;
    if result.is_err() {
        let _ = tokio::fs::remove_file(&temporary).await;
    }
    result
}

fn verify_bundle_reader(
    reader: &mut fs::File,
    expected_size: u64,
    expected_sha256: &str,
) -> Result<()> {
    use std::io::Seek;
    let metadata = reader.metadata()?;
    if !metadata.is_file() || metadata.len() != expected_size {
        bail!("appliance package snapshot size changed")
    }
    reader.rewind()?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    let mut total = 0u64;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| anyhow!("appliance package snapshot length overflow"))?;
        if total > expected_size {
            bail!("appliance package snapshot exceeded its signed size")
        }
        hasher.update(&buffer[..read]);
    }
    if total != expected_size || hex::encode(hasher.finalize()) != expected_sha256 {
        bail!("appliance package snapshot integrity check failed")
    }
    Ok(())
}

fn extract_snapshot(bundle: &mut fs::File, output: &Path) -> Result<()> {
    let decoder = zstd::Decoder::new(bundle).context("open appliance package snapshot")?;
    let mut archive = tar::Archive::new(decoder);
    let mut names = BTreeSet::new();
    let mut extracted_bytes = 0u64;
    for entry in archive
        .entries()
        .context("read appliance package snapshot")?
    {
        let mut entry = entry.context("read appliance package entry")?;
        let path = entry.path().context("read appliance package path")?;
        let Some(name) = archive_root_name(&path)? else {
            if entry.header().entry_type().is_dir() {
                continue;
            }
            bail!("appliance package snapshot has an unnamed entry")
        };
        if !entry.header().entry_type().is_file()
            || !is_allowed_snapshot_filename(&name)
            || !names.insert(name.clone())
        {
            bail!("appliance package snapshot contains an unsafe entry")
        }
        extracted_bytes = extracted_bytes
            .checked_add(entry.size())
            .ok_or_else(|| anyhow!("appliance package snapshot expanded size overflow"))?;
        if extracted_bytes > 32 * 1024 * 1024 * 1024u64 {
            bail!("appliance package snapshot expands beyond its limit")
        }
        let destination = output.join(&name);
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&destination)
            .with_context(|| format!("create appliance package file {name}"))?;
        std::io::copy(&mut entry, &mut file)?;
        file.sync_all()?;
    }
    for required in [
        "Packages",
        "Packages.gz",
        "Release",
        "SHA256SUMS",
        "UBUNTU-SNAPSHOT-ID",
    ] {
        if !names.contains(required) {
            bail!("appliance package snapshot omitted {required}")
        }
    }
    if !names.iter().any(|name| name.ends_with(".deb")) {
        bail!("appliance package snapshot contains no Debian packages")
    }
    Ok(())
}

fn archive_root_name(path: &Path) -> Result<Option<String>> {
    let mut name = None;
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(value) if name.is_none() => {
                name = Some(
                    value
                        .to_str()
                        .ok_or_else(|| anyhow!("appliance package path is not UTF-8"))?
                        .to_string(),
                );
            }
            _ => bail!("appliance package snapshot path escapes its root"),
        }
    }
    Ok(name)
}

fn is_allowed_snapshot_filename(name: &str) -> bool {
    let metadata = matches!(
        name,
        "Packages" | "Packages.gz" | "Release" | "SHA256SUMS" | "UBUNTU-SNAPSHOT-ID"
    );
    (metadata || name.ends_with(".deb"))
        && !name.is_empty()
        && name.len() <= 255
        && name.is_ascii()
        && !name.chars().any(|character| {
            character.is_control() || character.is_whitespace() || matches!(character, '/' | '\\')
        })
}

fn verify_extracted_snapshot(directory: &Path, release: &SignedApplianceRelease) -> Result<()> {
    let snapshot_id = fs::read_to_string(directory.join("UBUNTU-SNAPSHOT-ID"))?;
    if snapshot_id != format!("{}\n", release.ubuntu_snapshot_id) {
        bail!("appliance package Ubuntu snapshot identifier changed")
    }
    let checksums = fs::read_to_string(directory.join("SHA256SUMS"))?;
    if checksums.len() > 8 * 1024 * 1024 || checksums.is_empty() {
        bail!("appliance package checksum manifest is invalid")
    }
    let mut covered = BTreeSet::new();
    for line in checksums.lines() {
        let (digest, filename) = line
            .split_once("  ")
            .ok_or_else(|| anyhow!("appliance package checksum line is invalid"))?;
        require_sha256(digest)?;
        let filename = filename.strip_prefix("./").unwrap_or(filename);
        if !is_allowed_snapshot_filename(filename)
            || filename == "SHA256SUMS"
            || filename == "UBUNTU-SNAPSHOT-ID"
            || !covered.insert(filename.to_string())
        {
            bail!("appliance package checksum target is invalid")
        }
        let path = directory.join(filename);
        let mut file = fs::File::open(&path)?;
        let size = file.metadata()?.len();
        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; 1024 * 1024];
        let mut read_total = 0u64;
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            read_total += read as u64;
            hasher.update(&buffer[..read]);
        }
        if read_total != size || hex::encode(hasher.finalize()) != digest {
            bail!("appliance package file checksum changed")
        }
    }
    let actual_files = fs::read_dir(directory)?
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            entry
                .file_type()
                .ok()
                .filter(|kind| kind.is_file())
                .map(|_| entry.file_name().to_string_lossy().to_string())
        })
        .filter(|name| name != "SHA256SUMS" && name != "UBUNTU-SNAPSHOT-ID")
        .collect::<BTreeSet<_>>();
    if covered != actual_files {
        bail!("appliance package checksum coverage is incomplete")
    }

    let packages = fs::read_to_string(directory.join("Packages"))?;
    if packages.len() > 16 * 1024 * 1024 {
        bail!("appliance package index is too large")
    }
    let mut indexed_versions = BTreeMap::new();
    for stanza in packages.split("\n\n") {
        let mut package = None;
        let mut version = None;
        for line in stanza.lines() {
            if let Some(value) = line.strip_prefix("Package: ") {
                package = Some(value);
            } else if let Some(value) = line.strip_prefix("Version: ") {
                version = Some(value);
            }
        }
        if let (Some(package), Some(version)) = (package, version) {
            indexed_versions.insert(package.to_string(), version.to_string());
        }
    }
    for (package, expected_version) in &release.required_package_versions {
        if indexed_versions.get(package) != Some(expected_version) {
            bail!("appliance package index does not contain the signed required version")
        }
    }
    Ok(())
}

fn write_atomic_json(path: &Path, value: &impl Serialize, mode: u32) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("appliance state path has no parent"))?;
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| anyhow!("appliance state filename is invalid"))?,
        uuid::Uuid::new_v4()
    ));
    let body = serde_json::to_vec(value)?;
    let result = (|| -> Result<()> {
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)?;
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        file.write_all(&body)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        sync_directory(parent)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn sync_directory(path: &Path) -> Result<()> {
    fs::File::open(path)?.sync_all()?;
    Ok(())
}

fn canonical_base64(value: &str, expected_length: usize) -> Result<Vec<u8>> {
    if value.is_empty() || value.trim() != value || value.chars().any(char::is_whitespace) {
        bail!("appliance release signature material is not canonical Base64")
    }
    let decoded = STANDARD
        .decode(value.as_bytes())
        .context("decode appliance release signature material")?;
    if decoded.len() != expected_length || STANDARD.encode(&decoded) != value {
        bail!("appliance release signature material is not canonical Base64")
    }
    Ok(decoded)
}

fn canonical_json(value: Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut keys = object.keys().cloned().collect::<Vec<_>>();
            keys.sort();
            let mut sorted = serde_json::Map::new();
            for key in keys {
                if let Some(value) = object.get(&key) {
                    sorted.insert(key, canonical_json(value.clone()));
                }
            }
            Value::Object(sorted)
        }
        Value::Array(values) => Value::Array(values.into_iter().map(canonical_json).collect()),
        other => other,
    }
}

fn require_sha256(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("appliance package SHA-256 is invalid")
    }
    Ok(())
}

fn is_snapshot_id(value: &str) -> bool {
    value.len() == 16
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 => byte == b'T',
            15 => byte == b'Z',
            _ => byte.is_ascii_digit(),
        })
}

fn is_safe_token(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+' | b':' | b'~')
        })
}

pub fn store_network_change(change: Option<SignedApplianceNetworkChange>) -> Result<()> {
    let Some(change) = change else {
        return Ok(());
    };
    if !is_managed_ubuntu() {
        bail!("received an appliance network change on a non-appliance Forge host")
    }
    validate_network_change(&change, false)?;
    if read_optional_bounded_json::<Value>(Path::new(NETWORK_CHANGE_STATUS_PATH), 64 * 1024)
        .is_some_and(|status| {
            status.get("change_id").and_then(Value::as_str) == Some(change.id.to_string().as_str())
                && matches!(
                    status.get("status").and_then(Value::as_str),
                    Some("acknowledged" | "rolled_back" | "failed")
                )
        })
    {
        return Ok(());
    }
    if let Some(existing) = read_optional_bounded_json::<SignedApplianceNetworkChange>(
        Path::new(NETWORK_CHANGE_REQUEST_PATH),
        128 * 1024,
    ) {
        if existing.id == change.id && existing.signature == change.signature {
            return Ok(());
        }
        bail!("another appliance network change is already durable")
    }
    write_atomic_json(Path::new(NETWORK_CHANGE_REQUEST_PATH), &change, 0o600)?;
    write_atomic_json(
        Path::new(NETWORK_CHANGE_STATUS_PATH),
        &json!({
            "status":"requested",
            "stage":"queued",
            "change_id":change.id,
            "config_sha256":change.config_sha256,
            "candidate_sha256":"",
            "failure_code":"",
            "reported_at":Utc::now(),
        }),
        0o600,
    )
}

pub fn verify_and_materialize_network_change() -> Result<PathBuf> {
    let change: SignedApplianceNetworkChange =
        read_bounded_json(Path::new(NETWORK_CHANGE_REQUEST_PATH), 128 * 1024)?;
    validate_network_change(&change, false)?;
    let (interface_name, mac) = resolve_wired_interface(&change.network.interface_id)?;
    if fs::read_to_string(format!("/sys/class/net/{interface_name}/operstate"))
        .unwrap_or_default()
        .trim()
        != "up"
    {
        bail!("managed wired interface has no link")
    }
    if change.network.mode == "static" {
        let address = change
            .network
            .address_cidr
            .as_deref()
            .and_then(|value| value.split('/').next())
            .ok_or_else(|| anyhow!("static network address is missing"))?;
        let status = std::process::Command::new("arping")
            .args(["-D", "-q", "-c", "2", "-I", &interface_name, address])
            .status()
            .context("run network duplicate-address detection")?;
        if !status.success() {
            bail!("static network address is already in use")
        }
    }
    let mut device = serde_json::Map::new();
    device.insert("match".to_string(), json!({"macaddress":mac}));
    device.insert("set-name".to_string(), json!(interface_name));
    device.insert("dhcp6".to_string(), json!(false));
    if change.network.mode == "dhcp" {
        device.insert("dhcp4".to_string(), json!(true));
    } else {
        device.insert("dhcp4".to_string(), json!(false));
        device.insert(
            "addresses".to_string(),
            json!([change.network.address_cidr]),
        );
        device.insert(
            "routes".to_string(),
            json!([{"to":"default","via":change.network.gateway}]),
        );
        device.insert(
            "nameservers".to_string(),
            json!({"addresses":change.network.dns_servers}),
        );
    }
    let candidate = canonical_json(json!({
        "network": {
            "version": 2,
            "renderer": "networkd",
            "ethernets": {"cybex-forge": Value::Object(device)},
        }
    }));
    let output_root = Path::new("/run/cybex-forge-network-change");
    fs::create_dir_all(output_root)?;
    fs::set_permissions(output_root, fs::Permissions::from_mode(0o700))?;
    let output = output_root.join(format!("{}.yaml", change.id));
    write_atomic_json(&output, &candidate, 0o600)?;
    Ok(output)
}

pub fn pending_network_acknowledgement() -> Result<Option<PendingApplianceNetworkAcknowledgement>> {
    if !Path::new(NETWORK_CHANGE_REQUEST_PATH).is_file()
        || !Path::new(NETWORK_PENDING_PATH).is_file()
    {
        return Ok(None);
    }
    let change: SignedApplianceNetworkChange =
        read_bounded_json(Path::new(NETWORK_CHANGE_REQUEST_PATH), 128 * 1024)?;
    validate_network_change(&change, false)?;
    let candidate_sha256 = fs::read_to_string(NETWORK_PENDING_PATH)?;
    let candidate_sha256 = candidate_sha256
        .strip_suffix('\n')
        .ok_or_else(|| anyhow!("pending Netplan hash is not canonical"))?
        .to_string();
    require_sha256(&candidate_sha256)?;
    Ok(Some(PendingApplianceNetworkAcknowledgement {
        change_id: change.id,
        candidate_sha256,
    }))
}

pub fn accept_network_acknowledgement(
    acknowledgement: &SignedApplianceNetworkAcknowledgement,
) -> Result<()> {
    let change: SignedApplianceNetworkChange =
        read_bounded_json(Path::new(NETWORK_CHANGE_REQUEST_PATH), 128 * 1024)?;
    validate_network_change(&change, false)?;
    let state = load_provisioning_state()?;
    let pending = pending_network_acknowledgement()?
        .ok_or_else(|| anyhow!("no Netplan candidate is awaiting acknowledgement"))?;
    if acknowledgement.schema != "cybex.forge.network-ack.v1"
        || acknowledgement.change_id != change.id
        || acknowledgement.change_id != pending.change_id
        || acknowledgement.device_id != state.plan.reserved_device_id
        || acknowledgement.candidate_sha256 != pending.candidate_sha256
        || acknowledgement.expires_at <= Utc::now()
        || acknowledgement.expires_at <= acknowledgement.issued_at
        || acknowledgement.expires_at - acknowledgement.issued_at > chrono::Duration::minutes(2)
    {
        bail!("Management network acknowledgement does not match the pending candidate")
    }
    require_sha256(&acknowledgement.candidate_sha256)?;
    verify_management_signature(
        acknowledgement,
        "signature",
        &acknowledgement.signature,
        NETWORK_ACK_SIGNATURE_DOMAIN,
        &state.management_signing_public_key_b64,
    )?;
    write_atomic_bytes(
        Path::new(NETWORK_ACK_PATH),
        format!("{}\n", acknowledgement.candidate_sha256).as_bytes(),
        0o600,
    )
}

fn validate_network_change(
    change: &SignedApplianceNetworkChange,
    allow_expired: bool,
) -> Result<()> {
    let state = load_provisioning_state()?;
    if change.schema != "cybex.forge.network-change.v1"
        || change.id.is_nil()
        || change.device_incarnation_id.is_nil()
        || change.device_id != state.plan.reserved_device_id
        || change.revision <= 0
        || (!allow_expired && change.expires_at <= Utc::now())
        || change.expires_at <= change.issued_at
        || change.expires_at - change.issued_at > chrono::Duration::minutes(5)
    {
        bail!("appliance network change contract is invalid")
    }
    validate_network_input(&change.network)?;
    let network = canonical_json(serde_json::to_value(&change.network)?);
    if hex::encode(Sha256::digest(serde_json::to_vec(&network)?)) != change.config_sha256 {
        bail!("appliance network change digest does not match its body")
    }
    verify_management_signature(
        change,
        "signature",
        &change.signature,
        NETWORK_CHANGE_SIGNATURE_DOMAIN,
        &state.management_signing_public_key_b64,
    )
}

fn verify_management_signature<T: Serialize>(
    value: &T,
    signature_field: &str,
    signature: &str,
    domain: &str,
    public_key: &str,
) -> Result<()> {
    let key = canonical_base64(public_key, 32)?;
    let key = VerifyingKey::from_bytes(
        key.as_slice()
            .try_into()
            .map_err(|_| anyhow!("Management signing public key length is invalid"))?,
    )?;
    if key.is_weak() {
        bail!("Management signing public key is weak")
    }
    let signature = canonical_url_base64(signature, 64)?;
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| anyhow!("Management signature length is invalid"))?;
    let mut unsigned = serde_json::to_value(value)?;
    unsigned
        .as_object_mut()
        .ok_or_else(|| anyhow!("Management signed object is invalid"))?
        .remove(signature_field);
    let body = serde_json::to_vec(&canonical_json(unsigned))?;
    let mut payload = domain.as_bytes().to_vec();
    payload.push(b'\n');
    payload.extend_from_slice(&body);
    key.verify_strict(&payload, &Signature::from_bytes(&signature))?;
    Ok(())
}

fn canonical_url_base64(value: &str, expected_length: usize) -> Result<Vec<u8>> {
    if value.is_empty() || value.trim() != value || value.chars().any(char::is_whitespace) {
        bail!("Management signature is not canonical URL-safe Base64")
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(value.as_bytes())
        .context("decode Management signature")?;
    if decoded.len() != expected_length || URL_SAFE_NO_PAD.encode(&decoded) != value {
        bail!("Management signature is not canonical URL-safe Base64")
    }
    Ok(decoded)
}

fn load_provisioning_state() -> Result<crate::provisioning::DurableProvisioningState> {
    let state: crate::provisioning::DurableProvisioningState =
        read_bounded_json(Path::new(PROVISIONING_STATE_PATH), 512 * 1024)?;
    if state.schema != "cybex.forge.provisioning-state.v1"
        || state.management_signing_public_key_b64.is_empty()
        || !state.identity_active
    {
        bail!("installed provisioning identity cannot verify Management changes")
    }
    Ok(state)
}

fn validate_network_input(network: &ApplianceNetworkInput) -> Result<()> {
    if network.interface_id.is_empty()
        || network.interface_id.len() > 256
        || network.interface_id != network.interface_id.trim()
        || network.interface_id.chars().any(char::is_control)
    {
        bail!("managed network interface identity is invalid")
    }
    match network.mode.as_str() {
        "dhcp" => {
            if network.address_cidr.is_some()
                || network.gateway.is_some()
                || !network.dns_servers.is_empty()
            {
                bail!("DHCP network change contains static settings")
            }
        }
        "static" => {
            let (address, prefix) = network
                .address_cidr
                .as_deref()
                .and_then(|value| value.split_once('/'))
                .ok_or_else(|| anyhow!("static network address is invalid"))?;
            let address: std::net::Ipv4Addr = address.parse()?;
            let prefix: u8 = prefix.parse()?;
            let gateway: std::net::Ipv4Addr = network
                .gateway
                .as_deref()
                .ok_or_else(|| anyhow!("static network gateway is missing"))?
                .parse()?;
            if prefix > 32 || address == gateway || !same_ipv4_subnet(address, gateway, prefix) {
                bail!("static network address and gateway are incompatible")
            }
            if network.dns_servers.is_empty()
                || network.dns_servers.len() > 4
                || network
                    .dns_servers
                    .iter()
                    .any(|value| value.parse::<std::net::Ipv4Addr>().is_err())
            {
                bail!("static network DNS servers are invalid")
            }
        }
        _ => bail!("managed network mode is unsupported"),
    }
    Ok(())
}

fn same_ipv4_subnet(left: std::net::Ipv4Addr, right: std::net::Ipv4Addr, prefix: u8) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    u32::from(left) & mask == u32::from(right) & mask
}

fn resolve_wired_interface(stable_id: &str) -> Result<(String, String)> {
    let mut matches = Vec::new();
    for entry in fs::read_dir("/sys/class/net")? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        let root = entry.path();
        if name == "lo"
            || root.join("wireless").exists()
            || fs::read_to_string(root.join("type"))?.trim() != "1"
            || !root.join("device").exists()
        {
            continue;
        }
        let mac = fs::read_to_string(root.join("address"))?
            .trim()
            .to_ascii_lowercase();
        let output = std::process::Command::new("udevadm")
            .args([
                "info",
                "--query=property",
                &format!("--path={}", root.display()),
            ])
            .output()?;
        if !output.status.success() || output.stdout.len() > 1024 * 1024 {
            bail!("could not resolve managed wired interface identity")
        }
        let properties = String::from_utf8(output.stdout)?;
        let id = properties
            .lines()
            .find_map(|line| line.strip_prefix("ID_PATH="))
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| format!("mac-{mac}"));
        if id == stable_id {
            matches.push((name, mac));
        }
    }
    if matches.len() != 1 {
        bail!("managed wired interface identity is missing or ambiguous")
    }
    Ok(matches.remove(0))
}

fn write_atomic_bytes(path: &Path, body: &[u8], mode: u32) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("appliance state path has no parent"))?;
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(".network.{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| -> Result<()> {
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)?;
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        file.write_all(body)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        sync_directory(parent)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

pub async fn report() -> Result<Option<ApplianceReport>> {
    if !is_managed_ubuntu() {
        return Ok(None);
    }
    let release: ApplianceRelease = read_bounded_json(Path::new(RELEASE_PATH), 64 * 1024)?;
    if release.schema != "cybex.forge.appliance-release.v1"
        || release.release_id.is_empty()
        || release.ubuntu_snapshot_id.is_empty()
    {
        bail!("installed appliance release metadata is invalid")
    }
    let installed: Value = read_bounded_json(Path::new(INSTALLED_STATE_PATH), 64 * 1024)?;
    if installed.get("at_rest_protection").and_then(Value::as_str) != Some("none")
        || installed.get("base_os").and_then(Value::as_str) != Some("ubuntu")
        || installed.get("base_os_version").and_then(Value::as_str) != Some("26.04")
    {
        bail!("installed appliance state is invalid")
    }
    let package_update = read_optional_bounded_json(Path::new(UPDATE_STATUS_PATH), 128 * 1024)
        .unwrap_or_else(|| json!({"status":"idle"}));
    let managed_interface_id =
        read_optional_bounded_json::<Value>(Path::new(INSTALL_PLAN_PATH), 256 * 1024)
            .and_then(|plan| {
                plan.get("network")?
                    .get("interface_id")?
                    .as_str()
                    .map(str::to_owned)
            })
            .unwrap_or_default();
    let network = json!({
        "managed_interface_id": managed_interface_id,
        "interfaces": command_json("ip", &["-j", "address", "show"]).await,
        "network_fallback_active": Path::new(
            "/var/lib/cybex-forge/state/network-fallback-active"
        ).exists(),
        "network_change": read_optional_bounded_json::<Value>(
            Path::new(NETWORK_CHANGE_STATUS_PATH),
            64 * 1024,
        ).unwrap_or_else(|| json!({"status":"idle"})),
    });
    let local_health = local_health().await;
    Ok(Some(ApplianceReport {
        base_os: "ubuntu".to_string(),
        base_os_version: "26.04".to_string(),
        appliance_release: release.release_id,
        ubuntu_snapshot_id: release.ubuntu_snapshot_id,
        root_generation: installed
            .get("root_generation")
            .and_then(Value::as_str)
            .unwrap_or(&release.root_generation)
            .to_string(),
        kernel_version: command_text("uname", &["-r"]).await,
        secure_boot: secure_boot_enabled(),
        boot_mode: if Path::new("/sys/firmware/efi").is_dir() {
            "uefi".to_string()
        } else {
            "legacy".to_string()
        },
        firmware_version: read_trimmed("/sys/class/dmi/id/bios_version"),
        microcode_version: microcode_version(),
        nix_version: command_text("nix", &["--version"]).await,
        at_rest_protection: "none".to_string(),
        network,
        package_update,
        local_health,
    }))
}

async fn local_health() -> Value {
    let mut checks = serde_json::Map::new();
    for unit in ["nginx", "tftpd-hpa", "nix-daemon"] {
        let healthy = Command::new("systemctl")
            .args(["is-active", "--quiet", unit])
            .status()
            .await
            .is_ok_and(|status| status.success());
        checks.insert(unit.to_string(), Value::Bool(healthy));
    }
    let status = if checks.values().all(|value| value == &Value::Bool(true)) {
        "healthy"
    } else {
        "degraded"
    };
    json!({"status":status,"checks":checks})
}

fn secure_boot_enabled() -> bool {
    fs::read_dir("/sys/firmware/efi/efivars")
        .ok()
        .into_iter()
        .flatten()
        .flatten()
        .any(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("SecureBoot-")
                && fs::read(entry.path())
                    .ok()
                    .is_some_and(|bytes| bytes.get(4) == Some(&1))
        })
}

fn microcode_version() -> String {
    fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|body| {
            body.lines().find_map(|line| {
                let (key, value) = line.split_once(':')?;
                (key.trim() == "microcode").then(|| value.trim().to_string())
            })
        })
        .unwrap_or_default()
}

async fn command_text(program: &str, arguments: &[&str]) -> String {
    Command::new(program)
        .args(arguments)
        .output()
        .await
        .ok()
        .filter(|output| output.status.success() && output.stdout.len() <= 1024 * 1024)
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .unwrap_or_default()
}

async fn command_json(program: &str, arguments: &[&str]) -> Value {
    serde_json::from_str(&command_text(program, arguments).await).unwrap_or(Value::Null)
}

fn read_trimmed(path: &str) -> String {
    fs::read_to_string(path)
        .map(|value| value.trim().chars().take(256).collect())
        .unwrap_or_default()
}

fn read_bounded_json<T: for<'de> Deserialize<'de>>(path: &Path, max: u64) -> Result<T> {
    let metadata = fs::metadata(path).with_context(|| format!("inspect {}", path.display()))?;
    if !metadata.is_file() || metadata.len() > max {
        bail!("appliance state file is invalid")
    }
    serde_json::from_slice(&fs::read(path)?).with_context(|| format!("parse {}", path.display()))
}

fn read_optional_bounded_json<T: for<'de> Deserialize<'de>>(path: &Path, max: u64) -> Option<T> {
    read_bounded_json(path, max).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_capability_is_versioned() {
        assert_eq!(APPLIANCE_UPDATE_CAPABILITY, "appliance_update_v1");
    }
}
