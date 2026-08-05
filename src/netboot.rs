use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    net::IpAddr,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use axum::{
    extract::{Path as AxumPath, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chrono::Utc;
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use rand::{RngCore, rngs::OsRng};
use reqwest::{Client, Url};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::{fs as tokio_fs, io::AsyncWriteExt, net::lookup_host};
use tracing::warn;

use crate::{
    AppState, assets,
    error::{AppError, AppResult},
};

pub const DESCRIPTOR_SCHEMA: &str = "cybex.forge.workstation-netboot.v1";
pub const MANIFEST_SCHEMA: &str = "cybex.forge.workstation-netboot-manifest.v1";
pub const SIGNATURE_DOMAIN: &str = "CYBEX-FORGE-WORKSTATION-NETBOOT-V1";
pub const ARCHITECTURE: &str = "x86_64-linux";
pub const FORMAT: &str = "split-squashfs-v1";
pub const REQUIRED_FORGE_PROTOCOL: u32 = 4;
pub const MAX_BUNDLE_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 256 * 1024;
const FAILURE_MESSAGE_MAX_CHARS: usize = 512;
const BOOT_GRANT_LIFETIME_SECONDS: i64 = 10 * 60;
const BOOT_SESSION_RETENTION_SECONDS: i64 = 24 * 60 * 60;
const BOOT_CONTEXT_MAX_BYTES: usize = 64 * 1024;
const BUNDLE_RETENTION_SECONDS: i64 = 7 * 24 * 60 * 60;
const SCRUB_INTERVAL_SECONDS: i64 = 24 * 60 * 60;
const MAINTENANCE_INTERVAL_SECONDS: u64 = 60 * 60;
const BOOT_GRANT_DOMAIN: &str = "CYBEX-FORGE-BOOT-GRANT-V1";
const COMPONENT_NAMES: [&str; 3] = ["bzImage", "initrd", "nix-store.squashfs"];

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ComponentDescriptor {
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ComponentDescriptors {
    #[serde(rename = "bzImage")]
    pub bz_image: ComponentDescriptor,
    pub initrd: ComponentDescriptor,
    #[serde(rename = "nix-store.squashfs")]
    pub nix_store_squashfs: ComponentDescriptor,
}

impl ComponentDescriptors {
    fn get(&self, name: &str) -> Option<&ComponentDescriptor> {
        match name {
            "bzImage" => Some(&self.bz_image),
            "initrd" => Some(&self.initrd),
            "nix-store.squashfs" => Some(&self.nix_store_squashfs),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WorkstationNetbootDescriptor {
    pub schema: String,
    pub runtime_version: String,
    pub manage_source_revision: String,
    pub nixpkgs_revision: String,
    pub architecture: String,
    pub format: String,
    pub required_forge_protocol: u32,
    pub url: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub manifest_sha256: String,
    pub components: ComponentDescriptors,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WorkstationNetbootManifest {
    schema: String,
    runtime_version: String,
    architecture: String,
    format: String,
    required_forge_protocol: u32,
    manage_source_revision: String,
    nixpkgs_revision: String,
    source_date_epoch: u64,
    toplevel: String,
    kernel_cmdline_template: String,
    components: ComponentDescriptors,
    provenance: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct BootGrantClaims {
    pub schema: &'static str,
    pub forge_device_id: String,
    pub organization_id: String,
    pub organization_slug: String,
    pub manage_api_url: String,
    pub bundle_sha256: String,
    pub profile_id: Option<String>,
    pub mac: String,
    pub managed_device_id: Option<String>,
    pub reinstall_request_id: Option<String>,
    pub issued_at: i64,
    pub expires_at: i64,
    pub nonce: String,
}

#[derive(Clone, Debug, Serialize)]
struct ForgeBootGrant {
    claims: BootGrantClaims,
    signature: String,
}

#[derive(Clone, Debug, Serialize)]
struct BootContext {
    schema: &'static str,
    api_url: String,
    organization_slug: String,
    bundle_sha256: String,
    profile_id: Option<String>,
    forge_boot_grant: ForgeBootGrant,
}

#[derive(Clone, Debug, Serialize)]
pub struct BootSessionLaunch {
    pub schema: &'static str,
    pub bundle_sha256: String,
    pub kernel_url: String,
    pub initrd_url: String,
    pub context_url: String,
    pub squashfs_url: String,
    pub command_line: String,
    pub expires_at: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DesiredWorkstationNetboot {
    pub descriptor: WorkstationNetbootDescriptor,
    pub reconcile_generation: i64,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct WorkstationNetbootReport {
    pub state: String,
    pub progress_percent: i64,
    pub bytes_downloaded: i64,
    pub total_bytes: i64,
    pub failure_kind: String,
    pub failure_message: String,
    pub desired_bundle_sha256: String,
    pub active_bundle_sha256: String,
    pub previous_bundle_sha256: String,
    pub runtime_version: String,
    pub last_verified_at: Option<String>,
}

pub fn signature_message(descriptor: &WorkstationNetbootDescriptor) -> String {
    format!(
        "{SIGNATURE_DOMAIN}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
        descriptor.runtime_version,
        descriptor.manage_source_revision,
        descriptor.nixpkgs_revision,
        descriptor.architecture,
        descriptor.format,
        descriptor.required_forge_protocol,
        descriptor.components.bz_image.size_bytes,
        descriptor.components.bz_image.sha256,
        descriptor.components.initrd.size_bytes,
        descriptor.components.initrd.sha256,
        descriptor.components.nix_store_squashfs.size_bytes,
        descriptor.components.nix_store_squashfs.sha256,
        descriptor.manifest_sha256,
        descriptor.size_bytes,
        descriptor.sha256,
        descriptor.url,
    )
}

pub fn validate_descriptor(
    descriptor: &WorkstationNetbootDescriptor,
    trusted_public_key: &str,
) -> Result<()> {
    validate_descriptor_with_policy(descriptor, trusted_public_key, false)
}

fn validate_descriptor_with_policy(
    descriptor: &WorkstationNetbootDescriptor,
    trusted_public_key: &str,
    allow_private_release_urls: bool,
) -> Result<()> {
    if descriptor.schema != DESCRIPTOR_SCHEMA {
        bail!("workstation netboot descriptor schema is unsupported");
    }
    Version::parse(&descriptor.runtime_version)
        .context("workstation netboot runtime version is not canonical SemVer")?;
    validate_revision(&descriptor.manage_source_revision, "Manage source revision")?;
    validate_revision(&descriptor.nixpkgs_revision, "nixpkgs revision")?;
    if descriptor.architecture != ARCHITECTURE
        || descriptor.format != FORMAT
        || descriptor.required_forge_protocol != REQUIRED_FORGE_PROTOCOL
    {
        bail!("workstation netboot descriptor target contract is incompatible");
    }
    validate_sha256(&descriptor.sha256, "bundle SHA-256")?;
    validate_sha256(&descriptor.manifest_sha256, "manifest SHA-256")?;
    if descriptor.size_bytes == 0 || descriptor.size_bytes > MAX_BUNDLE_BYTES {
        bail!("workstation netboot bundle size is outside its bound");
    }
    for name in COMPONENT_NAMES {
        let component = descriptor.components.get(name).expect("fixed component");
        validate_sha256(&component.sha256, "component SHA-256")?;
        if component.size_bytes == 0 || component.size_bytes > MAX_BUNDLE_BYTES {
            bail!("workstation netboot component size is outside its bound");
        }
    }
    let parsed_url = Url::parse(&descriptor.url).context("parse workstation netboot URL")?;
    if (!allow_private_release_urls && parsed_url.scheme() != "https")
        || (allow_private_release_urls && !matches!(parsed_url.scheme(), "http" | "https"))
        || parsed_url.host_str().is_none()
        || !parsed_url.username().is_empty()
        || parsed_url.password().is_some()
        || parsed_url.fragment().is_some()
    {
        bail!("workstation netboot URL must be an uncredentialed public HTTPS URL");
    }
    let expected_name = format!(
        "cybex-workstation-netboot-{}-{}-{ARCHITECTURE}.tar.zst",
        descriptor.runtime_version,
        &descriptor.manage_source_revision[..12]
    );
    if parsed_url
        .path_segments()
        .and_then(Iterator::last)
        .is_none_or(|name| name != expected_name)
    {
        bail!("workstation netboot URL does not bind the canonical filename");
    }

    let key_bytes = STANDARD
        .decode(trusted_public_key.trim())
        .context("decode workstation netboot trusted public key")?;
    let key_array: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| anyhow!("workstation netboot trusted public key must be 32 bytes"))?;
    let key = VerifyingKey::from_bytes(&key_array).context("parse workstation netboot key")?;
    if key.is_weak() {
        bail!("workstation netboot trusted public key must not be weak");
    }
    let signature_bytes = STANDARD
        .decode(descriptor.signature.trim())
        .context("decode workstation netboot signature")?;
    if STANDARD.encode(&signature_bytes) != descriptor.signature {
        bail!("workstation netboot signature is not canonical Base64");
    }
    let signature =
        Signature::from_slice(&signature_bytes).context("parse workstation netboot signature")?;
    key.verify(signature_message(descriptor).as_bytes(), &signature)
        .context("verify workstation netboot signature")?;
    Ok(())
}

pub async fn reconcile_desired(
    state: &AppState,
    desired: &DesiredWorkstationNetboot,
) -> Result<()> {
    if desired.reconcile_generation < 0 {
        bail!("workstation netboot reconcile generation must not be negative");
    }
    validate_descriptor_with_policy(
        &desired.descriptor,
        &state.config.update.trusted_public_key,
        state.config.workstation_netboot.allow_private_release_urls,
    )?;
    let descriptor_json = serde_json::to_string(&desired.descriptor)?;
    let descriptor_sha256 = sha256_bytes(descriptor_json.as_bytes());
    enforce_watermark(state, &desired.descriptor, &descriptor_sha256).await?;

    sqlx::query(
        "UPDATE workstation_netboot_runtime
         SET desired_descriptor_json = ?, desired_descriptor_sha256 = ?, reconcile_generation = ?,
             state = 'queued', progress_percent = 0, bytes_downloaded = 0, total_bytes = ?,
             failure_kind = '', failure_message = '', updated_at = ?
         WHERE singleton_id = 1",
    )
    .bind(&descriptor_json)
    .bind(&descriptor_sha256)
    .bind(desired.reconcile_generation)
    .bind(i64::try_from(desired.descriptor.size_bytes).unwrap_or(i64::MAX))
    .bind(now())
    .execute(&state.db)
    .await?;

    if crate::maintenance::lease_active()? {
        set_runtime_state(state, "held", 0, 0, desired.descriptor.size_bytes).await?;
        return Ok(());
    }

    let existing_ready: Option<(String,)> = sqlx::query_as(
        "SELECT bundle_sha256 FROM workstation_netboot_bundles
         WHERE bundle_sha256 = ? AND retention_state = 'verified'",
    )
    .bind(&desired.descriptor.sha256)
    .fetch_optional(&state.db)
    .await?;
    if existing_ready.is_some() {
        promote_existing(
            state,
            &desired.descriptor,
            &descriptor_json,
            &descriptor_sha256,
            desired.reconcile_generation,
        )
        .await?;
        return Ok(());
    }

    let imported = match import_bundle(state, &desired.descriptor).await {
        Ok(imported) => imported,
        Err(error) => {
            record_failure(
                state,
                classify_failure(&error),
                &safe_failure_message(&error),
            )
            .await?;
            return Err(error);
        }
    };
    if !imported {
        return Ok(());
    }
    promote_existing(
        state,
        &desired.descriptor,
        &descriptor_json,
        &descriptor_sha256,
        desired.reconcile_generation,
    )
    .await
}

async fn import_bundle(
    state: &AppState,
    descriptor: &WorkstationNetbootDescriptor,
) -> Result<bool> {
    let private_root = state.config.paths.data_dir.join("netboot");
    let staging_root = private_root.join("staging");
    let public_root = state.config.paths.boot_assets_dir.join("netboot");
    let extraction_root = public_root.join(".staging");
    tokio_fs::create_dir_all(&staging_root).await?;
    tokio_fs::create_dir_all(&public_root).await?;
    tokio_fs::create_dir_all(&extraction_root).await?;
    crate::disk::ensure_headroom(
        &private_root,
        descriptor.size_bytes.saturating_mul(2),
        "workstation netboot import",
    )?;

    set_runtime_state(state, "downloading", 1, 0, descriptor.size_bytes).await?;
    let part = staging_root.join(format!("{}.tar.zst.part", descriptor.sha256));
    download_bundle(state, descriptor, &part).await?;
    set_runtime_state(
        state,
        "verifying",
        70,
        descriptor.size_bytes,
        descriptor.size_bytes,
    )
    .await?;
    let actual = sha256_file(part.clone()).await?;
    if actual != descriptor.sha256 {
        tokio_fs::remove_file(&part).await.ok();
        bail!("workstation netboot bundle SHA-256 mismatch");
    }

    set_runtime_state(
        state,
        "extracting",
        80,
        descriptor.size_bytes,
        descriptor.size_bytes,
    )
    .await?;
    if crate::maintenance::lease_active()? {
        set_runtime_state(
            state,
            "held",
            80,
            descriptor.size_bytes,
            descriptor.size_bytes,
        )
        .await?;
        return Ok(false);
    }
    // systemd exposes the private data and served roots as separate writable
    // bind mounts. Keep extraction on the served filesystem so the final
    // promotion remains an atomic rename; this dot-directory is outside every
    // routed HTTP namespace.
    let stage = extraction_root.join(format!("{}.{}", descriptor.sha256, uuid::Uuid::new_v4()));
    let part_for_extract = part.clone();
    let stage_for_extract = stage.clone();
    let descriptor_for_extract = descriptor.clone();
    let extraction = tokio::task::spawn_blocking(move || {
        extract_and_verify(
            &part_for_extract,
            &stage_for_extract,
            &descriptor_for_extract,
        )
    })
    .await;
    let extraction = match extraction {
        Ok(result) => result,
        Err(error) => {
            fs::remove_dir_all(&stage).ok();
            tokio_fs::remove_file(&part).await.ok();
            return Err(error).context("join workstation netboot extraction");
        }
    };
    if let Err(error) = extraction {
        fs::remove_dir_all(&stage).ok();
        tokio_fs::remove_file(&part).await.ok();
        return Err(error);
    }

    if crate::maintenance::lease_active()? {
        fs::remove_dir_all(&stage).context("remove held netboot staging tree")?;
        set_runtime_state(
            state,
            "held",
            90,
            descriptor.size_bytes,
            descriptor.size_bytes,
        )
        .await?;
        return Ok(false);
    }

    let final_root = public_root.join(&descriptor.sha256);
    if final_root.exists() {
        fs::remove_dir_all(&stage).context("remove duplicate netboot staging tree")?;
    } else {
        fs::rename(&stage, &final_root).context("atomically publish workstation netboot")?;
        sync_directory(&public_root)?;
    }
    tokio_fs::remove_file(&part).await.ok();

    let verified_at = now();
    sqlx::query(
        "INSERT INTO workstation_netboot_bundles
         (bundle_sha256, runtime_version, manage_source_revision, nixpkgs_revision,
          architecture, manifest_sha256, descriptor_json, root_path, size_bytes,
          retention_state, verified_at, last_scrubbed_at, retained_until,
          created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'verified', ?, ?, ?, ?, ?)
         ON CONFLICT(bundle_sha256) DO UPDATE SET
           descriptor_json = excluded.descriptor_json,
           root_path = excluded.root_path,
           retention_state = 'verified',
           verified_at = excluded.verified_at,
           last_scrubbed_at = excluded.last_scrubbed_at,
           retained_until = excluded.retained_until,
           quarantined_at = NULL,
           quarantine_reason = '',
           updated_at = excluded.updated_at",
    )
    .bind(&descriptor.sha256)
    .bind(&descriptor.runtime_version)
    .bind(&descriptor.manage_source_revision)
    .bind(&descriptor.nixpkgs_revision)
    .bind(&descriptor.architecture)
    .bind(&descriptor.manifest_sha256)
    .bind(serde_json::to_string(descriptor)?)
    .bind(final_root.display().to_string())
    .bind(i64::try_from(descriptor.size_bytes).unwrap_or(i64::MAX))
    .bind(&verified_at)
    .bind(&verified_at)
    .bind(retained_until())
    .bind(&verified_at)
    .bind(&verified_at)
    .execute(&state.db)
    .await?;
    Ok(true)
}

async fn download_bundle(
    state: &AppState,
    descriptor: &WorkstationNetbootDescriptor,
    part: &Path,
) -> Result<()> {
    let mut offset = match tokio_fs::symlink_metadata(part).await {
        Ok(metadata)
            if metadata.file_type().is_file()
                && metadata.nlink() == 1
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.permissions().mode() & 0o777 == 0o600 =>
        {
            metadata.len()
        }
        Ok(_) => bail!("workstation netboot partial path is not a regular file"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
        Err(error) => return Err(error.into()),
    };
    if offset > descriptor.size_bytes {
        tokio_fs::remove_file(part).await?;
        offset = 0;
    }
    if offset == descriptor.size_bytes {
        return Ok(());
    }
    let (client, url) = public_release_client(
        &descriptor.url,
        state.config.workstation_netboot.allow_private_release_urls,
    )
    .await?;
    let mut request = client.get(url);
    if offset > 0 {
        request = request.header(header::RANGE, format!("bytes={offset}-"));
    }
    let mut response = request
        .send()
        .await
        .context("download workstation netboot bundle")?;
    let expected_status = if offset > 0 {
        StatusCode::PARTIAL_CONTENT
    } else {
        StatusCode::OK
    };
    if response.status() != expected_status {
        bail!("workstation netboot download returned an unexpected HTTP status");
    }
    let remaining = descriptor.size_bytes - offset;
    if response.content_length() != Some(remaining) {
        bail!("workstation netboot download length did not match the signed descriptor");
    }
    if offset > 0 {
        let expected = format!(
            "bytes {offset}-{}/{}",
            descriptor.size_bytes - 1,
            descriptor.size_bytes
        );
        if response
            .headers()
            .get(header::CONTENT_RANGE)
            .and_then(|value| value.to_str().ok())
            != Some(expected.as_str())
        {
            bail!("workstation netboot resume response had an invalid Content-Range");
        }
    }
    let mut options = tokio_fs::OpenOptions::new();
    options
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = options.open(part).await?;
    let mut downloaded = offset;
    while let Some(chunk) = response
        .chunk()
        .await
        .context("read workstation netboot body")?
    {
        downloaded = downloaded
            .checked_add(chunk.len() as u64)
            .ok_or_else(|| anyhow!("workstation netboot download size overflow"))?;
        if downloaded > descriptor.size_bytes {
            bail!("workstation netboot download exceeded its signed size");
        }
        file.write_all(&chunk).await?;
        let progress = 1 + ((downloaded.saturating_mul(68) / descriptor.size_bytes) as i64);
        set_runtime_state(
            state,
            "downloading",
            progress,
            downloaded,
            descriptor.size_bytes,
        )
        .await?;
    }
    file.flush().await?;
    file.sync_all().await?;
    if downloaded != descriptor.size_bytes {
        bail!("workstation netboot download was truncated");
    }
    Ok(())
}

async fn public_release_client(
    value: &str,
    allow_private_release_urls: bool,
) -> Result<(Client, Url)> {
    let url = Url::parse(value)?;
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("workstation netboot URL has no host"))?;
    let port = url.port_or_known_default().unwrap_or(443);
    let addresses = lookup_host((host, port))
        .await
        .context("resolve workstation netboot release host")?
        .collect::<BTreeSet<_>>();
    if addresses.is_empty()
        || (!allow_private_release_urls && addresses.iter().any(|address| !public_ip(address.ip())))
    {
        bail!("workstation netboot release host did not resolve exclusively to public addresses");
    }
    let addresses = addresses.into_iter().collect::<Vec<_>>();
    let builder = Client::builder()
        .timeout(Duration::from_secs(30 * 60))
        .connect_timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .resolve_to_addrs(host, &addresses);
    Ok((builder.build()?, url))
}

fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            !(ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_documentation()
                || ip.is_unspecified()
                || ip.is_multicast()
                || octets[0] == 0
                || octets[0] >= 240
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
                || (octets[0] == 192 && octets[1] == 88 && octets[2] == 99)
                || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19)))
        }
        IpAddr::V6(ip) => {
            if let Some(ipv4) = ip.to_ipv4_mapped() {
                return public_ip(IpAddr::V4(ipv4));
            }
            let segments = ip.segments();
            !(ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || segments[0] & 0xe000 != 0x2000
                || (segments[0] == 0x2001 && segments[1] == 0x0db8)
                || (segments[0] == 0x2001 && segments[1] == 0x0002))
        }
    }
}

fn extract_and_verify(
    archive_path: &Path,
    stage: &Path,
    descriptor: &WorkstationNetbootDescriptor,
) -> Result<()> {
    fs::create_dir(stage).context("create workstation netboot extraction directory")?;
    fs::set_permissions(stage, fs::Permissions::from_mode(0o755))?;
    let file = fs::File::open(archive_path)?;
    let decoder = zstd::Decoder::new(file).context("open workstation netboot zstd stream")?;
    let mut archive = tar::Archive::new(decoder);
    let mut seen = BTreeSet::new();
    let mut ordered_names = Vec::new();
    let mut archive_mtime = None;
    for entry in archive
        .entries()
        .context("read workstation netboot tar entries")?
    {
        let mut entry = entry?;
        if entry.pax_extensions()?.is_some() || entry.header().as_ustar().is_none() {
            bail!("workstation netboot archive extensions are not permitted");
        }
        let path = entry.path()?.into_owned();
        let name = single_component_name(&path)?;
        if !seen.insert(name.clone()) {
            bail!("workstation netboot archive contains a duplicate entry");
        }
        if name != "manifest.json" && !COMPONENT_NAMES.contains(&name.as_str()) {
            bail!("workstation netboot archive contains an unexpected entry");
        }
        if !entry.header().entry_type().is_file()
            || entry.header().uid()? != 0
            || entry.header().gid()? != 0
            || entry.header().mode()? != 0o644
        {
            bail!("workstation netboot archive entry metadata is unsafe");
        }
        let mtime = entry.header().mtime()?;
        if archive_mtime
            .replace(mtime)
            .is_some_and(|previous| previous != mtime)
        {
            bail!("workstation netboot archive timestamps are inconsistent");
        }
        ordered_names.push(name.clone());
        let declared_size = if name == "manifest.json" {
            if entry.size() == 0 || entry.size() > MAX_MANIFEST_BYTES {
                bail!("workstation netboot manifest size is outside its bound");
            }
            entry.size()
        } else {
            let expected = descriptor
                .components
                .get(&name)
                .expect("allowlisted component");
            if entry.size() != expected.size_bytes {
                bail!("workstation netboot archive component size does not match descriptor");
            }
            expected.size_bytes
        };
        let target = stage.join(&name);
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true).mode(0o644);
        let mut output = options.open(&target)?;
        // The service intentionally runs with UMask=0077. Restore the signed
        // public component mode explicitly before checking and publishing it.
        output.set_permissions(fs::Permissions::from_mode(0o644))?;
        let copied = std::io::copy(&mut entry, &mut output)?;
        if copied != declared_size {
            bail!("workstation netboot archive entry was truncated");
        }
        output.sync_all()?;
    }
    let expected_names = BTreeSet::from([
        "manifest.json".to_string(),
        "bzImage".to_string(),
        "initrd".to_string(),
        "nix-store.squashfs".to_string(),
    ]);
    if seen != expected_names {
        bail!("workstation netboot archive did not contain the exact component set");
    }
    if ordered_names != ["bzImage", "initrd", "manifest.json", "nix-store.squashfs"] {
        bail!("workstation netboot archive entries are not sorted");
    }
    let manifest_body = fs::read(stage.join("manifest.json"))?;
    if sha256_bytes(&manifest_body) != descriptor.manifest_sha256 {
        bail!("workstation netboot manifest SHA-256 mismatch");
    }
    let manifest = parse_canonical_manifest(&manifest_body)?;
    validate_manifest(&manifest, descriptor)?;
    if archive_mtime != Some(manifest.source_date_epoch) {
        bail!("workstation netboot archive timestamp does not match its manifest");
    }
    verify_extracted_tree(stage, descriptor)?;
    sync_directory(stage)?;
    Ok(())
}

fn verify_extracted_tree(root: &Path, descriptor: &WorkstationNetbootDescriptor) -> Result<()> {
    let metadata = fs::symlink_metadata(root)?;
    if !metadata.file_type().is_dir() {
        bail!("workstation netboot bundle root is not a directory");
    }
    let mut names = BTreeSet::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow!("workstation netboot bundle filename is not UTF-8"))?;
        if !names.insert(name.clone()) {
            bail!("workstation netboot bundle contains duplicate files");
        }
        if name != "manifest.json" && !COMPONENT_NAMES.contains(&name.as_str()) {
            bail!("workstation netboot bundle contains an unexpected file");
        }
        let metadata = fs::symlink_metadata(entry.path())?;
        if !metadata.file_type().is_file()
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o777 != 0o644
        {
            bail!("workstation netboot bundle file metadata is unsafe");
        }
    }
    let expected_names = BTreeSet::from([
        "manifest.json".to_string(),
        "bzImage".to_string(),
        "initrd".to_string(),
        "nix-store.squashfs".to_string(),
    ]);
    if names != expected_names {
        bail!("workstation netboot bundle does not contain its exact component set");
    }
    let manifest_body = fs::read(root.join("manifest.json"))?;
    if manifest_body.is_empty()
        || manifest_body.len() as u64 > MAX_MANIFEST_BYTES
        || sha256_bytes(&manifest_body) != descriptor.manifest_sha256
    {
        bail!("workstation netboot manifest SHA-256 mismatch");
    }
    let manifest = parse_canonical_manifest(&manifest_body)?;
    validate_manifest(&manifest, descriptor)?;
    for name in COMPONENT_NAMES {
        let expected = descriptor.components.get(name).expect("fixed component");
        let path = root.join(name);
        if fs::metadata(&path)?.len() != expected.size_bytes
            || sha256_regular_file(&path)? != expected.sha256
        {
            bail!("workstation netboot component integrity mismatch");
        }
    }
    Ok(())
}

fn validate_manifest(
    manifest: &WorkstationNetbootManifest,
    descriptor: &WorkstationNetbootDescriptor,
) -> Result<()> {
    if manifest.schema != MANIFEST_SCHEMA
        || manifest.runtime_version != descriptor.runtime_version
        || manifest.architecture != descriptor.architecture
        || manifest.format != descriptor.format
        || manifest.required_forge_protocol != descriptor.required_forge_protocol
        || manifest.manage_source_revision != descriptor.manage_source_revision
        || manifest.nixpkgs_revision != descriptor.nixpkgs_revision
        || manifest.components != descriptor.components
    {
        bail!("workstation netboot manifest does not match its signed descriptor");
    }
    if !manifest.toplevel.starts_with("/nix/store/")
        || manifest.toplevel.contains(char::is_whitespace)
        || manifest
            .kernel_cmdline_template
            .matches("{squashfs_url}")
            .count()
            != 1
        || {
            let static_cmdline = manifest
                .kernel_cmdline_template
                .replace("{squashfs_url}", "");
            static_cmdline.contains('{') || static_cmdline.contains('}')
        }
        || manifest.provenance.is_empty()
    {
        bail!("workstation netboot manifest runtime metadata is invalid");
    }
    Ok(())
}

fn parse_canonical_manifest(body: &[u8]) -> Result<WorkstationNetbootManifest> {
    let value: serde_json::Value =
        serde_json::from_slice(body).context("parse workstation netboot manifest")?;
    let mut canonical =
        serde_json::to_vec(&value).context("serialize workstation netboot manifest")?;
    canonical.push(b'\n');
    if canonical != body {
        bail!("workstation netboot manifest is not canonical compact sorted JSON");
    }
    serde_json::from_value(value).context("validate workstation netboot manifest")
}

fn single_component_name(path: &Path) -> Result<String> {
    let mut components = path.components();
    let Some(Component::Normal(name)) = components.next() else {
        bail!("workstation netboot archive path is unsafe");
    };
    if components.next().is_some() {
        bail!("workstation netboot archive path is nested");
    }
    let name = name
        .to_str()
        .ok_or_else(|| anyhow!("workstation netboot archive path is not UTF-8"))?;
    if name.is_empty() || name.starts_with('.') {
        bail!("workstation netboot archive path is unsafe");
    }
    Ok(name.to_string())
}

async fn promote_existing(
    state: &AppState,
    descriptor: &WorkstationNetbootDescriptor,
    descriptor_json: &str,
    descriptor_sha256: &str,
    generation: i64,
) -> Result<()> {
    let key_fingerprint = sha256_bytes(
        &STANDARD
            .decode(state.config.update.trusted_public_key.trim())
            .context("decode workstation netboot trust key")?,
    );
    let now = now();
    let mut transaction = state.db.begin().await?;
    let candidate: Option<(String,)> = sqlx::query_as(
        "SELECT root_path FROM workstation_netboot_bundles
         WHERE bundle_sha256 = ? AND retention_state = 'verified'",
    )
    .bind(&descriptor.sha256)
    .fetch_optional(&mut *transaction)
    .await?;
    let (root_path,) = candidate
        .ok_or_else(|| anyhow!("workstation netboot candidate is not a verified local bundle"))?;
    let expected_root = state
        .config
        .paths
        .boot_assets_dir
        .join("netboot")
        .join(&descriptor.sha256);
    if Path::new(&root_path) != expected_root || !expected_root.is_dir() {
        bail!("workstation netboot verified bundle path is inconsistent");
    }
    let old_active: (String,) = sqlx::query_as(
        "SELECT active_bundle_sha256 FROM workstation_netboot_runtime WHERE singleton_id = 1",
    )
    .fetch_one(&mut *transaction)
    .await?;
    if !old_active.0.is_empty() && old_active.0 != descriptor.sha256 {
        sqlx::query(
            "UPDATE workstation_netboot_bundles
             SET retained_until = ?, updated_at = ?
             WHERE bundle_sha256 = ? AND retention_state = 'verified'",
        )
        .bind(retained_until())
        .bind(&now)
        .bind(&old_active.0)
        .execute(&mut *transaction)
        .await?;
    }
    sqlx::query(
        "UPDATE workstation_netboot_bundles
         SET retained_until = NULL, updated_at = ?
         WHERE bundle_sha256 = ? AND retention_state = 'verified'",
    )
    .bind(&now)
    .bind(&descriptor.sha256)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "UPDATE workstation_netboot_runtime
         SET desired_descriptor_json = ?, desired_descriptor_sha256 = ?, reconcile_generation = ?,
             state = 'ready', progress_percent = 100, bytes_downloaded = ?, total_bytes = ?,
             failure_kind = '', failure_message = '',
             previous_bundle_sha256 = CASE
                 WHEN active_bundle_sha256 <> '' AND active_bundle_sha256 <> ? THEN active_bundle_sha256
                 ELSE previous_bundle_sha256 END,
             active_bundle_sha256 = ?, watermark_key_fingerprint = ?,
             watermark_architecture = ?, watermark_runtime_version = ?,
             watermark_descriptor_sha256 = ?, last_verified_at = ?, updated_at = ?
         WHERE singleton_id = 1",
    )
    .bind(descriptor_json)
    .bind(descriptor_sha256)
    .bind(generation)
    .bind(i64::try_from(descriptor.size_bytes).unwrap_or(i64::MAX))
    .bind(i64::try_from(descriptor.size_bytes).unwrap_or(i64::MAX))
    .bind(&descriptor.sha256)
    .bind(&descriptor.sha256)
    .bind(key_fingerprint)
    .bind(&descriptor.architecture)
    .bind(&descriptor.runtime_version)
    .bind(descriptor_sha256)
    .bind(&now)
    .bind(&now)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(())
}

async fn enforce_watermark(
    state: &AppState,
    descriptor: &WorkstationNetbootDescriptor,
    descriptor_sha256: &str,
) -> Result<()> {
    let row: (String, String, String, String) = sqlx::query_as(
        "SELECT watermark_key_fingerprint, watermark_architecture,
                watermark_runtime_version, watermark_descriptor_sha256
         FROM workstation_netboot_runtime WHERE singleton_id = 1",
    )
    .fetch_one(&state.db)
    .await?;
    let key_fingerprint = sha256_bytes(
        &STANDARD
            .decode(state.config.update.trusted_public_key.trim())
            .context("decode workstation netboot trust key")?,
    );
    if row.0.is_empty() || row.0 != key_fingerprint || row.1 != descriptor.architecture {
        return Ok(());
    }
    enforce_watermark_precedence(
        &row.2,
        &row.3,
        &descriptor.runtime_version,
        descriptor_sha256,
    )
}

fn enforce_watermark_precedence(
    accepted_version: &str,
    accepted_descriptor_sha256: &str,
    candidate_version: &str,
    candidate_descriptor_sha256: &str,
) -> Result<()> {
    let accepted =
        Version::parse(accepted_version).context("stored netboot watermark is invalid")?;
    let candidate = Version::parse(candidate_version)?;
    if candidate < accepted {
        bail!("workstation netboot signed downgrade was rejected");
    }
    if candidate == accepted && accepted_descriptor_sha256 != candidate_descriptor_sha256 {
        bail!("workstation netboot descriptor changed at the accepted runtime version");
    }
    Ok(())
}

pub fn boot_grant_message(claims: &BootGrantClaims) -> String {
    format!(
        "{BOOT_GRANT_DOMAIN}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
        claims.forge_device_id,
        claims.organization_id,
        claims.organization_slug,
        claims.manage_api_url,
        claims.bundle_sha256,
        claims.profile_id.as_deref().unwrap_or_default(),
        claims.mac,
        claims.managed_device_id.as_deref().unwrap_or_default(),
        claims.reinstall_request_id.as_deref().unwrap_or_default(),
        claims.issued_at,
        claims.expires_at,
        claims.nonce,
    )
}

pub async fn create_boot_session(
    state: &AppState,
    normalized_mac: &str,
    profile_id: Option<&str>,
    managed_device_id: Option<&str>,
    reinstall_request_id: Option<&str>,
) -> Result<BootSessionLaunch> {
    crate::models::normalize_mac(normalized_mac)
        .map_err(|_| anyhow!("boot session MAC is invalid"))?;
    for (label, value) in [
        ("profile", profile_id),
        ("reinstall request", reinstall_request_id),
    ] {
        if let Some(value) = value {
            uuid::Uuid::parse_str(value)
                .with_context(|| format!("boot session {label} identity is invalid"))?;
        }
    }
    if managed_device_id.is_some_and(|value| !is_safe_control_plane_id(value)) {
        bail!("boot session managed device identity is invalid");
    }
    uuid::Uuid::parse_str(&state.config.manage.organization_id)
        .context("boot session organization identity is invalid")?;
    validate_organization_slug(&state.config.manage.organization_slug)?;

    let active: Option<(String, String, String)> = sqlx::query_as(
        "SELECT runtime.active_bundle_sha256, bundle.descriptor_json, bundle.root_path
         FROM workstation_netboot_runtime runtime
         JOIN workstation_netboot_bundles bundle
           ON bundle.bundle_sha256 = runtime.active_bundle_sha256
         WHERE runtime.singleton_id = 1 AND runtime.state = 'ready'",
    )
    .fetch_optional(&state.db)
    .await?;
    let (bundle_sha256, descriptor_json, root_path) =
        active.ok_or_else(|| anyhow!("workstation netboot runtime is not ready"))?;
    let descriptor: WorkstationNetbootDescriptor =
        serde_json::from_str(&descriptor_json).context("parse active netboot descriptor")?;
    if descriptor.sha256 != bundle_sha256 {
        bail!("active workstation netboot identity is inconsistent");
    }
    let manifest_body = fs::read(Path::new(&root_path).join("manifest.json"))
        .context("read active workstation netboot manifest")?;
    if sha256_bytes(&manifest_body) != descriptor.manifest_sha256 {
        bail!("active workstation netboot manifest failed its identity check");
    }
    let manifest = parse_canonical_manifest(&manifest_body)?;
    validate_manifest(&manifest, &descriptor)?;

    let identity = crate::manage::forge_boot_identity(&state.config)?;
    if !is_safe_control_plane_id(&identity.device_id) {
        bail!("adopted Forge device identity is invalid");
    }
    let issued_at = Utc::now().timestamp();
    let expires_at = issued_at + BOOT_GRANT_LIFETIME_SECONDS;
    let cleanup_after = issued_at + BOOT_SESSION_RETENTION_SECONDS;
    let mut nonce_bytes = [0_u8; 32];
    let mut session_bytes = [0_u8; 16];
    OsRng.fill_bytes(&mut nonce_bytes);
    OsRng.fill_bytes(&mut session_bytes);
    let nonce = URL_SAFE_NO_PAD.encode(nonce_bytes);
    let session_id = URL_SAFE_NO_PAD.encode(session_bytes);
    let claims = BootGrantClaims {
        schema: "cybex.forge.boot-grant.v1",
        forge_device_id: identity.device_id,
        organization_id: state.config.manage.organization_id.clone(),
        organization_slug: state.config.manage.organization_slug.clone(),
        manage_api_url: state.config.manage.api_url.clone(),
        bundle_sha256: bundle_sha256.clone(),
        profile_id: profile_id.map(ToOwned::to_owned),
        mac: normalized_mac.to_string(),
        managed_device_id: managed_device_id.map(ToOwned::to_owned),
        reinstall_request_id: reinstall_request_id.map(ToOwned::to_owned),
        issued_at,
        expires_at,
        nonce,
    };
    let signature = identity
        .signing_key
        .sign(boot_grant_message(&claims).as_bytes());
    let context = BootContext {
        schema: "cybex.forge.boot-context.v1",
        api_url: claims.manage_api_url.clone(),
        organization_slug: claims.organization_slug.clone(),
        bundle_sha256: bundle_sha256.clone(),
        profile_id: claims.profile_id.clone(),
        forge_boot_grant: ForgeBootGrant {
            claims,
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        },
    };
    let context_body = serde_json::to_vec(&context).context("serialize Forge boot context")?;
    let context_archive = newc_context_archive(&context_body, issued_at)?;
    if context_archive.len() > BOOT_CONTEXT_MAX_BYTES {
        bail!("Forge boot context archive exceeded 64 KiB");
    }

    let sessions_root = state.config.paths.data_dir.join("netboot/sessions");
    let session_root = sessions_root.join(&session_id);
    fs::create_dir_all(&sessions_root).context("create Forge boot sessions root")?;
    fs::set_permissions(&sessions_root, fs::Permissions::from_mode(0o700))?;
    fs::create_dir(&session_root).context("create Forge boot session directory")?;
    fs::set_permissions(&session_root, fs::Permissions::from_mode(0o700))?;
    let context_path = session_root.join("context.cpio");
    // iPXE's magic-initrd support wraps this bounded JSON body in the cpio
    // entry named by render_ipxe_launch. Supplying a second standalone cpio
    // after the compressed NixOS initrd is not reliable on the UEFI path.
    let write_result = write_private_file(&context_path, &context_body);
    if let Err(error) = write_result {
        fs::remove_dir_all(&session_root).ok();
        return Err(error);
    }

    let insert_result = sqlx::query(
        "INSERT INTO forge_boot_sessions
         (session_id, nonce_sha256, normalized_mac, profile_id, managed_device_id,
          reinstall_request_id, bundle_sha256, context_path, issued_at, expires_at,
          cleanup_after)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&session_id)
    .bind(sha256_bytes(&nonce_bytes))
    .bind(normalized_mac)
    .bind(profile_id)
    .bind(managed_device_id)
    .bind(reinstall_request_id)
    .bind(&bundle_sha256)
    .bind(context_path.display().to_string())
    .bind(issued_at)
    .bind(expires_at)
    .bind(cleanup_after)
    .execute(&state.db)
    .await;
    if let Err(error) = insert_result {
        fs::remove_dir_all(&session_root).ok();
        return Err(error.into());
    }
    sync_directory(&sessions_root)?;

    let public_base = state.config.public_base_url();
    let kernel_url = format!("{public_base}/netboot/{bundle_sha256}/bzImage");
    let initrd_url = format!("{public_base}/netboot/{bundle_sha256}/initrd");
    let squashfs_url = format!("{public_base}/netboot/{bundle_sha256}/nix-store.squashfs");
    let context_url = format!("{public_base}/boot-session/{session_id}/context.cpio");
    let command_line = manifest
        .kernel_cmdline_template
        .replace("{squashfs_url}", &squashfs_url);
    Ok(BootSessionLaunch {
        schema: "cybex.forge.kexec.v1",
        bundle_sha256,
        kernel_url,
        initrd_url,
        context_url,
        squashfs_url,
        command_line,
        expires_at,
    })
}

fn is_safe_control_plane_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value == value.trim()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

pub fn render_ipxe_launch(launch: &BootSessionLaunch) -> String {
    format!(
        "#!ipxe\necho Cybex Forge: loading signed workstation installer runtime\nkernel {} {} || goto failed\ninitrd {} || goto failed\ninitrd --name context.json {} /etc/cybex-installer/boot-context.json mode=600 mkdir=1 || goto failed\nboot || goto failed\n:failed\necho Cybex Forge could not stage the installer runtime\nsleep 5\nexit 1\n",
        launch.kernel_url, launch.command_line, launch.initrd_url, launch.context_url,
    )
}

pub async fn serve_context(
    State(state): State<AppState>,
    AxumPath(session_id): AxumPath<String>,
    headers: HeaderMap,
) -> AppResult<Response> {
    if !valid_session_id(&session_id) {
        return Err(AppError::NotFound);
    }
    let row: Option<(String, i64)> = sqlx::query_as(
        "SELECT context_path, expires_at FROM forge_boot_sessions WHERE session_id = ?",
    )
    .bind(&session_id)
    .fetch_optional(&state.db)
    .await?;
    let (stored_path, expires_at) = row.ok_or(AppError::NotFound)?;
    if expires_at < Utc::now().timestamp() {
        return Err(AppError::NotFound);
    }
    let expected_root = state
        .config
        .paths
        .data_dir
        .join("netboot/sessions")
        .join(&session_id);
    let expected_path = expected_root.join("context.cpio");
    if Path::new(&stored_path) != expected_path {
        return Err(AppError::NotFound);
    }
    let mut response =
        assets::serve_file_from_root(&expected_root, "context.cpio", &headers).await?;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        "application/vnd.cybex.boot-context"
            .parse()
            .map_err(|_| AppError::Config("invalid context content type".to_string()))?,
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        "no-store, max-age=0"
            .parse()
            .map_err(|_| AppError::Config("invalid context cache policy".to_string()))?,
    );
    Ok(response)
}

pub async fn cleanup_expired_sessions(state: &AppState) -> Result<usize> {
    let now_unix = Utc::now().timestamp();
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT session_id, context_path FROM forge_boot_sessions
         WHERE cleanup_after < ? ORDER BY cleanup_after LIMIT 256",
    )
    .bind(now_unix)
    .fetch_all(&state.db)
    .await?;
    let sessions_root = state.config.paths.data_dir.join("netboot/sessions");
    let mut removed = 0;
    for (session_id, context_path) in rows {
        if !valid_session_id(&session_id) {
            continue;
        }
        let root = sessions_root.join(&session_id);
        if Path::new(&context_path) != root.join("context.cpio") {
            continue;
        }
        match fs::symlink_metadata(&root) {
            Ok(metadata) if metadata.file_type().is_dir() => {
                fs::remove_dir_all(&root).context("remove expired Forge boot session")?;
            }
            Ok(_) => continue,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        sqlx::query("DELETE FROM forge_boot_sessions WHERE session_id = ? AND cleanup_after < ?")
            .bind(&session_id)
            .bind(now_unix)
            .execute(&state.db)
            .await?;
        removed += 1;
    }
    Ok(removed)
}

pub fn spawn_maintenance(state: AppState) {
    tokio::spawn(async move {
        loop {
            if let Err(error) = maintain_once(&state).await {
                warn!(
                    failure_kind = classify_failure(&error),
                    "workstation netboot maintenance failed"
                );
            }
            tokio::time::sleep(Duration::from_secs(MAINTENANCE_INTERVAL_SECONDS)).await;
        }
    });
}

async fn maintain_once(state: &AppState) -> Result<()> {
    cleanup_expired_sessions(state).await?;
    scrub_due_bundles(state).await?;
    prune_expired_bundles(state).await?;
    Ok(())
}

async fn scrub_due_bundles(state: &AppState) -> Result<usize> {
    let cutoff = (Utc::now() - chrono::Duration::seconds(SCRUB_INTERVAL_SECONDS))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT bundle.bundle_sha256, bundle.descriptor_json, bundle.root_path
         FROM workstation_netboot_bundles bundle
         JOIN workstation_netboot_runtime runtime ON runtime.singleton_id = 1
         WHERE bundle.retention_state = 'verified'
           AND (bundle.bundle_sha256 = runtime.active_bundle_sha256
                OR bundle.bundle_sha256 = runtime.previous_bundle_sha256)
           AND (bundle.last_scrubbed_at IS NULL OR bundle.last_scrubbed_at < ?)
         ORDER BY CASE WHEN bundle.bundle_sha256 = runtime.active_bundle_sha256 THEN 0 ELSE 1 END",
    )
    .bind(cutoff)
    .fetch_all(&state.db)
    .await?;
    let mut scrubbed = 0;
    for (bundle_sha256, descriptor_json, root_path) in rows {
        let verification =
            verify_stored_bundle(state, &bundle_sha256, &descriptor_json, &root_path).await;
        match verification {
            Ok(()) => {
                sqlx::query(
                    "UPDATE workstation_netboot_bundles
                     SET last_scrubbed_at = ?, updated_at = ?
                     WHERE bundle_sha256 = ? AND retention_state = 'verified'",
                )
                .bind(now())
                .bind(now())
                .bind(&bundle_sha256)
                .execute(&state.db)
                .await?;
                scrubbed += 1;
            }
            Err(_) => {
                quarantine_bundle(state, &bundle_sha256, &root_path).await?;
            }
        }
    }
    Ok(scrubbed)
}

async fn verify_stored_bundle(
    state: &AppState,
    bundle_sha256: &str,
    descriptor_json: &str,
    root_path: &str,
) -> Result<()> {
    validate_sha256(bundle_sha256, "stored bundle SHA-256")?;
    let descriptor: WorkstationNetbootDescriptor =
        serde_json::from_str(descriptor_json).context("parse stored workstation descriptor")?;
    if descriptor.sha256 != bundle_sha256 {
        bail!("stored workstation descriptor identity is inconsistent");
    }
    validate_descriptor_with_policy(
        &descriptor,
        &state.config.update.trusted_public_key,
        state.config.workstation_netboot.allow_private_release_urls,
    )?;
    let expected_root = state
        .config
        .paths
        .boot_assets_dir
        .join("netboot")
        .join(bundle_sha256);
    if Path::new(root_path) != expected_root {
        bail!("stored workstation bundle path is inconsistent");
    }
    tokio::task::spawn_blocking(move || verify_extracted_tree(&expected_root, &descriptor))
        .await
        .context("join workstation netboot scrub")?
}

async fn quarantine_bundle(state: &AppState, bundle_sha256: &str, root_path: &str) -> Result<()> {
    validate_sha256(bundle_sha256, "quarantined bundle SHA-256")?;
    let expected_root = state
        .config
        .paths
        .boot_assets_dir
        .join("netboot")
        .join(bundle_sha256);
    if Path::new(root_path) != expected_root {
        bail!("refusing to quarantine an unexpected workstation bundle path");
    }
    let quarantine_root = state
        .config
        .paths
        .boot_assets_dir
        .join("netboot-quarantine");
    fs::create_dir_all(&quarantine_root)?;
    fs::set_permissions(&quarantine_root, fs::Permissions::from_mode(0o700))?;
    let quarantined_path = quarantine_root.join(format!(
        "{}.{}",
        bundle_sha256,
        uuid::Uuid::new_v4().simple()
    ));
    match fs::symlink_metadata(&expected_root) {
        Ok(metadata) if metadata.file_type().is_dir() => {
            fs::rename(&expected_root, &quarantined_path)
                .context("atomically quarantine corrupt workstation bundle")?;
            sync_directory(
                expected_root
                    .parent()
                    .ok_or_else(|| anyhow!("workstation bundle has no parent"))?,
            )?;
            sync_directory(&quarantine_root)?;
        }
        Ok(_) => bail!("corrupt workstation bundle root is not a directory"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let timestamp = now();
    sqlx::query(
        "UPDATE workstation_netboot_bundles
         SET retention_state = 'quarantined', root_path = ?, quarantined_at = ?,
             quarantine_reason = 'integrity_mismatch', updated_at = ?
         WHERE bundle_sha256 = ?",
    )
    .bind(quarantined_path.display().to_string())
    .bind(&timestamp)
    .bind(&timestamp)
    .bind(bundle_sha256)
    .execute(&state.db)
    .await?;

    let runtime: (String, String) = sqlx::query_as(
        "SELECT active_bundle_sha256, previous_bundle_sha256
         FROM workstation_netboot_runtime WHERE singleton_id = 1",
    )
    .fetch_one(&state.db)
    .await?;
    if runtime.0 == bundle_sha256 {
        let fallback = find_verified_fallback(state, bundle_sha256).await?;
        let (state_name, active) = fallback
            .map(|identity| ("ready", identity))
            .unwrap_or_else(|| ("failed", String::new()));
        sqlx::query(
            "UPDATE workstation_netboot_runtime
             SET state = ?, active_bundle_sha256 = ?, previous_bundle_sha256 = '',
                 failure_kind = 'integrity_mismatch',
                 failure_message = 'active workstation runtime failed integrity verification',
                 progress_percent = CASE WHEN ? = 'ready' THEN 100 ELSE 0 END,
                 last_verified_at = CASE WHEN ? = 'ready' THEN ? ELSE last_verified_at END,
                 updated_at = ?
             WHERE singleton_id = 1",
        )
        .bind(state_name)
        .bind(active)
        .bind(state_name)
        .bind(state_name)
        .bind(&timestamp)
        .bind(&timestamp)
        .execute(&state.db)
        .await?;
    } else if runtime.1 == bundle_sha256 {
        sqlx::query(
            "UPDATE workstation_netboot_runtime
             SET previous_bundle_sha256 = '', failure_kind = 'integrity_mismatch',
                 failure_message = 'previous workstation runtime failed integrity verification',
                 updated_at = ? WHERE singleton_id = 1",
        )
        .bind(&timestamp)
        .execute(&state.db)
        .await?;
    }
    Ok(())
}

async fn find_verified_fallback(state: &AppState, excluded: &str) -> Result<Option<String>> {
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT bundle.bundle_sha256, bundle.descriptor_json, bundle.root_path
         FROM workstation_netboot_bundles bundle
         JOIN workstation_netboot_runtime runtime ON runtime.singleton_id = 1
         WHERE bundle.retention_state = 'verified' AND bundle.bundle_sha256 <> ?
         ORDER BY CASE WHEN bundle.bundle_sha256 = runtime.previous_bundle_sha256 THEN 0 ELSE 1 END,
                  bundle.verified_at DESC
         LIMIT 8",
    )
    .bind(excluded)
    .fetch_all(&state.db)
    .await?;
    for (bundle_sha256, descriptor_json, root_path) in rows {
        if verify_stored_bundle(state, &bundle_sha256, &descriptor_json, &root_path)
            .await
            .is_ok()
        {
            sqlx::query(
                "UPDATE workstation_netboot_bundles
                 SET retained_until = NULL, last_scrubbed_at = ?, updated_at = ?
                 WHERE bundle_sha256 = ?",
            )
            .bind(now())
            .bind(now())
            .bind(&bundle_sha256)
            .execute(&state.db)
            .await?;
            return Ok(Some(bundle_sha256));
        }
        quarantine_tree_only(state, &bundle_sha256, &root_path).await?;
    }
    Ok(None)
}

async fn quarantine_tree_only(
    state: &AppState,
    bundle_sha256: &str,
    root_path: &str,
) -> Result<()> {
    let expected_root = state
        .config
        .paths
        .boot_assets_dir
        .join("netboot")
        .join(bundle_sha256);
    if Path::new(root_path) != expected_root {
        bail!("refusing to quarantine an unexpected workstation fallback path");
    }
    let quarantine_root = state
        .config
        .paths
        .boot_assets_dir
        .join("netboot-quarantine");
    fs::create_dir_all(&quarantine_root)?;
    fs::set_permissions(&quarantine_root, fs::Permissions::from_mode(0o700))?;
    let target = quarantine_root.join(format!(
        "{}.{}",
        bundle_sha256,
        uuid::Uuid::new_v4().simple()
    ));
    match fs::symlink_metadata(&expected_root) {
        Ok(metadata) if metadata.file_type().is_dir() => fs::rename(&expected_root, &target)?,
        Ok(_) => bail!("corrupt workstation fallback root is not a directory"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let timestamp = now();
    sqlx::query(
        "UPDATE workstation_netboot_bundles
         SET retention_state = 'quarantined', root_path = ?, quarantined_at = ?,
             quarantine_reason = 'integrity_mismatch', updated_at = ?
         WHERE bundle_sha256 = ?",
    )
    .bind(target.display().to_string())
    .bind(&timestamp)
    .bind(&timestamp)
    .bind(bundle_sha256)
    .execute(&state.db)
    .await?;
    Ok(())
}

async fn prune_expired_bundles(state: &AppState) -> Result<usize> {
    let now_text = now();
    let now_unix = Utc::now().timestamp();
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT bundle.bundle_sha256, bundle.root_path
         FROM workstation_netboot_bundles bundle
         JOIN workstation_netboot_runtime runtime ON runtime.singleton_id = 1
         WHERE bundle.retention_state = 'verified'
           AND bundle.retained_until IS NOT NULL AND bundle.retained_until < ?
           AND bundle.bundle_sha256 <> runtime.active_bundle_sha256
           AND bundle.bundle_sha256 <> runtime.previous_bundle_sha256
           AND NOT EXISTS (
             SELECT 1 FROM forge_boot_sessions session
             WHERE session.bundle_sha256 = bundle.bundle_sha256 AND session.expires_at >= ?
           )
         ORDER BY bundle.retained_until LIMIT 8",
    )
    .bind(&now_text)
    .bind(now_unix)
    .fetch_all(&state.db)
    .await?;
    let public_root = state.config.paths.boot_assets_dir.join("netboot");
    let mut removed = 0;
    for (bundle_sha256, root_path) in rows {
        validate_sha256(&bundle_sha256, "pruned bundle SHA-256")?;
        let root = public_root.join(&bundle_sha256);
        if Path::new(&root_path) != root {
            continue;
        }
        let tombstone = public_root.join(format!(".prune-{}", uuid::Uuid::new_v4().simple()));
        match fs::symlink_metadata(&root) {
            Ok(metadata) if metadata.file_type().is_dir() => {
                fs::rename(&root, &tombstone)?;
                sync_directory(&public_root)?;
            }
            Ok(_) => continue,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let result = sqlx::query(
            "DELETE FROM workstation_netboot_bundles
             WHERE bundle_sha256 = ? AND retention_state = 'verified' AND retained_until < ?",
        )
        .bind(&bundle_sha256)
        .bind(&now_text)
        .execute(&state.db)
        .await;
        match result {
            Ok(result) if result.rows_affected() == 1 => {
                if tombstone.exists() {
                    fs::remove_dir_all(&tombstone)?;
                    sync_directory(&public_root)?;
                }
                removed += 1;
            }
            Ok(_) => {
                if tombstone.exists() {
                    fs::rename(&tombstone, &root)?;
                    sync_directory(&public_root)?;
                }
            }
            Err(error) => {
                if tombstone.exists() {
                    fs::rename(&tombstone, &root)?;
                    sync_directory(&public_root)?;
                }
                return Err(error.into());
            }
        }
    }
    Ok(removed)
}

fn validate_organization_slug(value: &str) -> Result<()> {
    if value.len() < 2
        || value.len() > 64
        || value.starts_with('-')
        || value.ends_with('-')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        bail!("boot session organization slug is invalid");
    }
    Ok(())
}

fn valid_session_id(value: &str) -> bool {
    value.len() == 22
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        && URL_SAFE_NO_PAD
            .decode(value)
            .is_ok_and(|decoded| decoded.len() == 16)
}

fn write_private_file(path: &Path, body: &[u8]) -> Result<()> {
    let temporary = path.with_extension("cpio.tmp");
    let mut options = fs::OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = options.open(&temporary)?;
    std::io::Write::write_all(&mut file, body)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    sync_directory(
        path.parent()
            .ok_or_else(|| anyhow!("context path has no parent"))?,
    )
}

fn newc_context_archive(body: &[u8], mtime: i64) -> Result<Vec<u8>> {
    if mtime < 0 || body.is_empty() {
        bail!("Forge boot context archive inputs are invalid");
    }
    let mut archive = Vec::with_capacity(body.len() + 512);
    append_newc_entry(
        &mut archive,
        "etc/cybex-installer/boot-context.json",
        0o100600,
        mtime as u32,
        body,
    )?;
    append_newc_entry(&mut archive, "TRAILER!!!", 0, mtime as u32, &[])?;
    while archive.len() % 512 != 0 {
        archive.push(0);
    }
    Ok(archive)
}

fn append_newc_entry(
    archive: &mut Vec<u8>,
    name: &str,
    mode: u32,
    mtime: u32,
    body: &[u8],
) -> Result<()> {
    let name_size = name
        .len()
        .checked_add(1)
        .ok_or_else(|| anyhow!("CPIO name size overflow"))?;
    let file_size = u32::try_from(body.len()).context("CPIO body exceeds u32")?;
    let header = format!(
        "070701{ino:08x}{mode:08x}{uid:08x}{gid:08x}{nlink:08x}{mtime:08x}{file_size:08x}{devmajor:08x}{devminor:08x}{rdevmajor:08x}{rdevminor:08x}{name_size:08x}{check:08x}",
        ino = 1_u32,
        uid = 0_u32,
        gid = 0_u32,
        nlink = 1_u32,
        devmajor = 0_u32,
        devminor = 0_u32,
        rdevmajor = 0_u32,
        rdevminor = 0_u32,
        check = 0_u32,
    );
    if header.len() != 110 {
        bail!("CPIO header length is invalid");
    }
    archive.extend_from_slice(header.as_bytes());
    archive.extend_from_slice(name.as_bytes());
    archive.push(0);
    pad_four(archive);
    archive.extend_from_slice(body);
    pad_four(archive);
    Ok(())
}

fn pad_four(value: &mut Vec<u8>) {
    while value.len() % 4 != 0 {
        value.push(0);
    }
}

async fn set_runtime_state(
    state: &AppState,
    status: &str,
    progress: i64,
    downloaded: u64,
    total: u64,
) -> Result<()> {
    sqlx::query(
        "UPDATE workstation_netboot_runtime
         SET state = ?, progress_percent = ?, bytes_downloaded = ?, total_bytes = ?, updated_at = ?
         WHERE singleton_id = 1",
    )
    .bind(status)
    .bind(progress.clamp(0, 100))
    .bind(i64::try_from(downloaded).unwrap_or(i64::MAX))
    .bind(i64::try_from(total).unwrap_or(i64::MAX))
    .bind(now())
    .execute(&state.db)
    .await?;
    Ok(())
}

async fn record_failure(state: &AppState, kind: &str, message: &str) -> Result<()> {
    sqlx::query(
        "UPDATE workstation_netboot_runtime
         SET state = 'failed', failure_kind = ?, failure_message = ?, updated_at = ?
         WHERE singleton_id = 1",
    )
    .bind(kind)
    .bind(message)
    .bind(now())
    .execute(&state.db)
    .await?;
    Ok(())
}

pub async fn report(state: &AppState) -> Result<WorkstationNetbootReport> {
    #[derive(sqlx::FromRow)]
    struct RuntimeReportRow {
        state: String,
        progress_percent: i64,
        bytes_downloaded: i64,
        total_bytes: i64,
        failure_kind: String,
        failure_message: String,
        desired_descriptor_json: String,
        active_bundle_sha256: String,
        previous_bundle_sha256: String,
        last_verified_at: Option<String>,
        watermark_runtime_version: String,
    }

    let row = sqlx::query_as::<_, RuntimeReportRow>(
        "SELECT state, progress_percent, bytes_downloaded, total_bytes,
                    failure_kind, failure_message, desired_descriptor_json,
                    active_bundle_sha256, previous_bundle_sha256, last_verified_at,
                    watermark_runtime_version
             FROM workstation_netboot_runtime WHERE singleton_id = 1",
    )
    .fetch_one(&state.db)
    .await?;
    let desired_bundle_sha256 =
        serde_json::from_str::<WorkstationNetbootDescriptor>(&row.desired_descriptor_json)
            .map(|descriptor| descriptor.sha256)
            .unwrap_or_default();
    Ok(WorkstationNetbootReport {
        state: row.state,
        progress_percent: row.progress_percent,
        bytes_downloaded: row.bytes_downloaded,
        total_bytes: row.total_bytes,
        failure_kind: row.failure_kind,
        failure_message: row.failure_message,
        desired_bundle_sha256,
        active_bundle_sha256: row.active_bundle_sha256,
        previous_bundle_sha256: row.previous_bundle_sha256,
        last_verified_at: row.last_verified_at,
        runtime_version: row.watermark_runtime_version,
    })
}

pub async fn serve_component(
    State(state): State<AppState>,
    AxumPath((bundle_sha256, component)): AxumPath<(String, String)>,
    headers: HeaderMap,
) -> AppResult<Response> {
    validate_sha256(&bundle_sha256, "bundle SHA-256").map_err(|_| AppError::NotFound)?;
    if !COMPONENT_NAMES.contains(&component.as_str()) {
        return Err(AppError::NotFound);
    }
    let now_unix = Utc::now().timestamp();
    let allowed: (i64,) = sqlx::query_as(
        "SELECT EXISTS(
           SELECT 1 FROM workstation_netboot_bundles bundle
           WHERE bundle.bundle_sha256 = ? AND bundle.retention_state = 'verified'
             AND (
               EXISTS(
                 SELECT 1 FROM workstation_netboot_runtime
                 WHERE singleton_id = 1
                   AND (bundle.bundle_sha256 = active_bundle_sha256
                        OR bundle.bundle_sha256 = previous_bundle_sha256)
               ) OR EXISTS(
                 SELECT 1 FROM forge_boot_sessions session
                 WHERE session.bundle_sha256 = bundle.bundle_sha256 AND session.expires_at >= ?
               )
             )
         )",
    )
    .bind(&bundle_sha256)
    .bind(now_unix)
    .fetch_one(&state.db)
    .await?;
    if allowed.0 == 0 {
        return Err(AppError::NotFound);
    }
    let root = state
        .config
        .paths
        .boot_assets_dir
        .join("netboot")
        .join(&bundle_sha256);
    let mut response = assets::serve_file_from_root(&root, &component, &headers).await?;
    let content_type = match component.as_str() {
        "bzImage" => "application/vnd.cybex.kernel",
        "initrd" => "application/vnd.cybex.initrd",
        "nix-store.squashfs" => "application/vnd.cybex.squashfs",
        _ => unreachable!("component was allowlisted"),
    };
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        content_type
            .parse()
            .map_err(|_| AppError::Config("invalid netboot content type".to_string()))?,
    );
    response.headers_mut().insert(
        header::ETAG,
        format!("\"{bundle_sha256}-{component}\"")
            .parse()
            .map_err(|_| AppError::Config("invalid netboot ETag".to_string()))?,
    );
    sqlx::query(
        "UPDATE workstation_netboot_bundles SET last_served_at = ?, updated_at = ? WHERE bundle_sha256 = ?",
    )
    .bind(now())
    .bind(now())
    .bind(&bundle_sha256)
    .execute(&state.db)
    .await
    .ok();
    Ok(response)
}

pub async fn readiness(State(state): State<AppState>) -> Response {
    match report(&state).await {
        Ok(report) => (StatusCode::OK, axum::Json(report)).into_response(),
        Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}

fn validate_revision(value: &str, label: &str) -> Result<()> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("workstation netboot {label} must be lowercase 40-hex");
    }
    Ok(())
}

fn validate_sha256(value: &str, label: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("workstation netboot {label} must be lowercase 64-hex");
    }
    Ok(())
}

async fn sha256_file(path: PathBuf) -> Result<String> {
    tokio::task::spawn_blocking(move || sha256_regular_file(&path))
        .await
        .context("join workstation netboot hashing")?
}

fn sha256_regular_file(path: &Path) -> Result<String> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        bail!("workstation netboot component is not a regular file");
    }
    let mut options = fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = options.open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn sha256_bytes(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

fn sync_directory(path: &Path) -> Result<()> {
    let directory = fs::File::open(path)?;
    directory.sync_all()?;
    Ok(())
}

fn now() -> String {
    Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn retained_until() -> String {
    (Utc::now() + chrono::Duration::seconds(BUNDLE_RETENTION_SECONDS))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

pub fn safe_failure_message(error: &anyhow::Error) -> String {
    let text = error.to_string();
    text.chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .take(FAILURE_MESSAGE_MAX_CHARS)
        .collect()
}

fn classify_failure(error: &anyhow::Error) -> &'static str {
    let message = error.to_string().to_ascii_lowercase();
    if message.contains("signature")
        || message.contains("descriptor")
        || message.contains("watermark")
    {
        "invalid_descriptor"
    } else if message.contains("sha-256")
        || message.contains("manifest")
        || message.contains("archive")
    {
        "integrity_mismatch"
    } else if message.contains("disk space") {
        "insufficient_disk_space"
    } else if message.contains("http")
        || message.contains("resolve")
        || message.contains("download")
    {
        "network_or_server"
    } else {
        "local_io_or_processing"
    }
}

pub fn safe_failure_kind(error: &anyhow::Error) -> &'static str {
    classify_failure(error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_context_overlay_is_a_bounded_newc_member() {
        let body = br#"{"schema":"cybex.forge.boot-context.v1"}"#;
        let cpio = newc_context_archive(body, 1_700_000_000).unwrap();
        assert!(cpio.len() <= BOOT_CONTEXT_MAX_BYTES);
        assert!(
            cpio.windows(b"etc/cybex-installer/boot-context.json".len())
                .any(|window| window == b"etc/cybex-installer/boot-context.json")
        );
    }

    #[test]
    fn ipxe_launch_uses_magic_initrd_context_injection() {
        let launch = BootSessionLaunch {
            schema: "cybex.forge.kexec.v1",
            bundle_sha256: "a".repeat(64),
            kernel_url: "http://forge.test/kernel".to_string(),
            initrd_url: "http://forge.test/initrd".to_string(),
            context_url: "http://forge.test/context.cpio".to_string(),
            squashfs_url: "http://forge.test/rootfs".to_string(),
            command_line: "init=/nix/store/system/init".to_string(),
            expires_at: 1_700_000_600,
        };
        let script = render_ipxe_launch(&launch);
        assert!(script.contains("initrd http://forge.test/initrd"));
        assert!(script.contains(
            "http://forge.test/context.cpio /etc/cybex-installer/boot-context.json mode=600 mkdir=1"
        ));
    }

    #[test]
    fn signature_message_contract_is_exact() {
        let descriptor = fixture_descriptor();
        let message = signature_message(&descriptor);
        assert!(message.starts_with("CYBEX-FORGE-WORKSTATION-NETBOOT-V1\n1.0.0\n"));
        assert!(message.ends_with("https://releases.example.test/cybex-workstation-netboot-1.0.0-aaaaaaaaaaaa-x86_64-linux.tar.zst\n"));
        assert_eq!(message.lines().count(), 17);
    }

    #[test]
    fn public_address_policy_rejects_special_networks() {
        for value in [
            "127.0.0.1",
            "10.0.0.1",
            "100.64.0.1",
            "169.254.169.254",
            "192.0.0.1",
            "192.0.2.1",
            "198.18.0.1",
            "::1",
            "fc00::1",
            "fe80::1",
            "2001:db8::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(!public_ip(value.parse().unwrap()), "{value}");
        }
        assert!(public_ip("8.8.8.8".parse().unwrap()));
        assert!(public_ip("2606:4700:4700::1111".parse().unwrap()));
    }

    #[test]
    fn watermark_rejects_downgrade_and_changed_equal_version() {
        enforce_watermark_precedence("1.2.3", &"a".repeat(64), "1.2.2", &"a".repeat(64))
            .unwrap_err();
        enforce_watermark_precedence("1.2.3", &"a".repeat(64), "1.2.3", &"b".repeat(64))
            .unwrap_err();
        enforce_watermark_precedence("1.2.3", &"a".repeat(64), "1.2.3", &"a".repeat(64)).unwrap();
        enforce_watermark_precedence("1.2.3", &"a".repeat(64), "1.3.0", &"b".repeat(64)).unwrap();
    }

    #[test]
    fn manifest_accepts_the_single_squashfs_url_placeholder() {
        let descriptor = fixture_descriptor();
        let manifest = fixture_manifest(&descriptor);
        validate_manifest(&manifest, &descriptor).unwrap();
    }

    #[test]
    fn manifest_rejects_other_cmdline_placeholders() {
        let descriptor = fixture_descriptor();
        let mut manifest = fixture_manifest(&descriptor);
        manifest.kernel_cmdline_template.push_str(" {unexpected}");
        validate_manifest(&manifest, &descriptor).unwrap_err();
    }

    fn fixture_manifest(descriptor: &WorkstationNetbootDescriptor) -> WorkstationNetbootManifest {
        WorkstationNetbootManifest {
            schema: MANIFEST_SCHEMA.to_string(),
            runtime_version: descriptor.runtime_version.clone(),
            architecture: descriptor.architecture.clone(),
            format: descriptor.format.clone(),
            required_forge_protocol: descriptor.required_forge_protocol,
            manage_source_revision: descriptor.manage_source_revision.clone(),
            nixpkgs_revision: descriptor.nixpkgs_revision.clone(),
            source_date_epoch: 1,
            toplevel: "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-system".to_string(),
            kernel_cmdline_template: "init=/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-system/init cybex.squashfs_url={squashfs_url}".to_string(),
            components: descriptor.components.clone(),
            provenance: BTreeMap::from([("agent".to_string(), "f".repeat(64))]),
        }
    }

    fn fixture_descriptor() -> WorkstationNetbootDescriptor {
        let component = ComponentDescriptor {
            sha256: "b".repeat(64),
            size_bytes: 1,
        };
        WorkstationNetbootDescriptor {
            schema: DESCRIPTOR_SCHEMA.to_string(),
            runtime_version: "1.0.0".to_string(),
            manage_source_revision: "a".repeat(40),
            nixpkgs_revision: "c".repeat(40),
            architecture: ARCHITECTURE.to_string(),
            format: FORMAT.to_string(),
            required_forge_protocol: REQUIRED_FORGE_PROTOCOL,
            url: "https://releases.example.test/cybex-workstation-netboot-1.0.0-aaaaaaaaaaaa-x86_64-linux.tar.zst".to_string(),
            sha256: "d".repeat(64),
            size_bytes: 4,
            manifest_sha256: "e".repeat(64),
            components: ComponentDescriptors {
                bz_image: component.clone(),
                initrd: component.clone(),
                nix_store_squashfs: component,
            },
            signature: String::new(),
        }
    }
}
