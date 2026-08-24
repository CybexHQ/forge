use super::protocol::{
    INSTALL_PLAN_SCHEMA_V1, INSTALL_PLAN_SCHEMA_V2, NETWORK_SNAPSHOT_DELIVERY, SignedInstallPlan,
};
use crate::{
    appliance::{
        SignedApplianceRelease, extract_snapshot_reader, validate_install_release,
        verify_thin_installer_snapshot,
    },
    release_transport,
};
use anyhow::{Context, Result, anyhow, bail};
use reqwest::{StatusCode, Url, header};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    ffi::CString,
    fs,
    net::IpAddr,
    os::unix::{ffi::OsStrExt, fs::PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::io::AsyncWriteExt;
use tokio_util::io::SyncIoBridge;

pub(crate) const EMBEDDED_REPOSITORY_PATH: &str = "/cdrom/cybex/apt";
pub(crate) const RELEASE_PUBLIC_KEY_PATH: &str = "/cdrom/cybex/release-public-key";
pub(crate) const STAGING_ROOT: &str = "/run/cybex-appliance-repo";
pub(crate) const STAGED_REPOSITORY_PATH: &str = "/run/cybex-appliance-repo/packages";

const MAX_SNAPSHOT_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_EXPANDED_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MINIMUM_TMPFS_HEADROOM: u64 = 128 * 1024 * 1024;
const TMPFS_MAGIC: i64 = 0x0102_1994;
const VERIFIED_MARKER: &str = ".verified-snapshot.json";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct VerifiedSnapshotMarker {
    schema: String,
    release_id: String,
    snapshot_sha256: String,
    snapshot_size_bytes: u64,
    release_signature: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MediaLayout {
    Embedded,
    Thin,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PackageDelivery {
    Embedded,
    NetworkSnapshot,
}

pub(crate) fn inspect_media_layout() -> Result<MediaLayout> {
    let path = Path::new(EMBEDDED_REPOSITORY_PATH);
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(MediaLayout::Thin),
        Err(error) => return Err(error).context("inspect embedded appliance repository"),
    };
    if !metadata.file_type().is_dir() {
        bail!("embedded appliance repository path is not a real directory")
    }
    for required in [
        "Packages",
        "Packages.gz",
        "Release",
        "SHA256SUMS",
        "UBUNTU-SNAPSHOT-ID",
    ] {
        let metadata = fs::symlink_metadata(path.join(required))
            .with_context(|| format!("inspect embedded appliance repository file {required}"))?;
        if !metadata.file_type().is_file() {
            bail!("embedded appliance repository file {required} is unsafe")
        }
    }
    if !fs::read_dir(path)?.any(|entry| {
        entry.is_ok_and(|entry| {
            entry.file_type().is_ok_and(|kind| kind.is_file())
                && entry.file_name().as_encoded_bytes().ends_with(b".deb")
        })
    }) {
        bail!("embedded appliance repository contains no Debian packages")
    }
    Ok(MediaLayout::Embedded)
}

pub(crate) fn validate_plan_delivery(
    plan: &SignedInstallPlan,
    layout: MediaLayout,
) -> Result<PackageDelivery> {
    match (plan.schema.as_str(), layout) {
        (INSTALL_PLAN_SCHEMA_V1, MediaLayout::Embedded) => Ok(PackageDelivery::Embedded),
        (INSTALL_PLAN_SCHEMA_V2, MediaLayout::Thin)
            if plan.package_delivery.as_deref() == Some(NETWORK_SNAPSHOT_DELIVERY)
                && plan.appliance_release.is_some()
                && plan.package_transport_url.is_some() =>
        {
            Ok(PackageDelivery::NetworkSnapshot)
        }
        (INSTALL_PLAN_SCHEMA_V1, MediaLayout::Thin) => {
            bail!("thin James media requires a signed network snapshot install plan")
        }
        (INSTALL_PLAN_SCHEMA_V2, MediaLayout::Embedded) => {
            bail!("embedded James media cannot use network snapshot delivery")
        }
        _ => bail!("install plan package delivery does not match this James media"),
    }
}

pub(crate) async fn stage_network_snapshot(
    plan: &SignedInstallPlan,
    release_public_key_path: &Path,
) -> Result<PathBuf> {
    let release = plan
        .appliance_release
        .as_ref()
        .ok_or_else(|| anyhow!("network snapshot plan omitted its appliance release"))?;
    validate_install_release(
        release,
        &plan.release_version,
        release_public_key_path,
        MAX_SNAPSHOT_BYTES,
    )?;
    let transport = plan
        .package_transport_url
        .as_deref()
        .ok_or_else(|| anyhow!("network snapshot plan omitted its transport URL"))?;
    validate_transport_url(transport, release)?;

    let staging_root = Path::new(STAGING_ROOT);
    ensure_staging_directory(staging_root)?;
    ensure_tmpfs_capacity(staging_root, 0)?;
    let repository = staging_root.join("packages");
    if reusable_repository(staging_root, &repository, release)? {
        return Ok(repository);
    }
    clear_repository_state(staging_root, &repository)?;
    remove_stale_candidates(staging_root)?;
    ensure_tmpfs_capacity(staging_root, required_staging_capacity(release)?)?;

    let candidate = staging_root.join(format!(".packages.{}", uuid::Uuid::new_v4()));
    fs::create_dir(&candidate).context("create volatile appliance repository candidate")?;
    fs::set_permissions(&candidate, fs::Permissions::from_mode(0o700))?;
    let result = download_extract_and_verify(transport, release, &candidate).await;
    if result.is_err() {
        let _ = fs::remove_dir_all(&candidate);
        return result.map(|_| repository);
    }
    for entry in fs::read_dir(&candidate)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            let _ = fs::remove_dir_all(&candidate);
            bail!("verified appliance repository contains a non-file entry")
        }
        fs::set_permissions(entry.path(), fs::Permissions::from_mode(0o444))?;
    }
    fs::set_permissions(&candidate, fs::Permissions::from_mode(0o555))?;
    fs::rename(&candidate, &repository).context("commit volatile appliance repository")?;
    write_verified_marker(staging_root, release)?;
    Ok(repository)
}

fn reusable_repository(
    staging_root: &Path,
    repository: &Path,
    release: &SignedApplianceRelease,
) -> Result<bool> {
    let repository_metadata = match fs::symlink_metadata(repository) {
        Ok(metadata) if metadata.file_type().is_dir() => Some(metadata),
        Ok(_) => bail!("volatile appliance repository path is unsafe"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error).context("inspect volatile appliance repository"),
    };
    let marker_path = staging_root.join(VERIFIED_MARKER);
    let marker_metadata = match fs::symlink_metadata(&marker_path) {
        Ok(metadata) if metadata.file_type().is_file() => Some(metadata),
        Ok(_) => bail!("volatile appliance repository marker is unsafe"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error).context("inspect volatile appliance repository marker"),
    };
    if repository_metadata.is_none() || marker_metadata.is_none() {
        return Ok(false);
    }
    let marker_bytes = fs::read(&marker_path)?;
    if marker_bytes.len() > 16 * 1024 {
        return Ok(false);
    }
    let Ok(marker) = serde_json::from_slice::<VerifiedSnapshotMarker>(&marker_bytes) else {
        return Ok(false);
    };
    let expected = verified_marker(release);
    Ok(marker.schema == expected.schema
        && marker.release_id == expected.release_id
        && marker.snapshot_sha256 == expected.snapshot_sha256
        && marker.snapshot_size_bytes == expected.snapshot_size_bytes
        && marker.release_signature == expected.release_signature
        && verify_thin_installer_snapshot(repository, release).is_ok())
}

fn clear_repository_state(staging_root: &Path, repository: &Path) -> Result<()> {
    match fs::symlink_metadata(repository) {
        Ok(metadata) if metadata.file_type().is_dir() => fs::remove_dir_all(repository)
            .context("remove invalid volatile appliance repository")?,
        Ok(_) => bail!("volatile appliance repository path is unsafe"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("inspect volatile appliance repository"),
    }
    let marker = staging_root.join(VERIFIED_MARKER);
    match fs::symlink_metadata(&marker) {
        Ok(metadata) if metadata.file_type().is_file() => fs::remove_file(marker)?,
        Ok(_) => bail!("volatile appliance repository marker is unsafe"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("inspect volatile appliance repository marker"),
    }
    Ok(())
}

fn verified_marker(release: &SignedApplianceRelease) -> VerifiedSnapshotMarker {
    VerifiedSnapshotMarker {
        schema: "cybex.james.verified-appliance-snapshot.v1".to_string(),
        release_id: release.release_id.clone(),
        snapshot_sha256: release.cybex_repository_snapshot.sha256.clone(),
        snapshot_size_bytes: release.cybex_repository_snapshot.size_bytes,
        release_signature: release.signature.clone(),
    }
}

fn write_verified_marker(staging_root: &Path, release: &SignedApplianceRelease) -> Result<()> {
    let marker = staging_root.join(VERIFIED_MARKER);
    let temporary = staging_root.join(format!(".verified-snapshot.{}.tmp", uuid::Uuid::new_v4()));
    let body = serde_json::to_vec(&verified_marker(release))?;
    let result = (|| -> Result<()> {
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)?;
        std::io::Write::write_all(&mut file, &body)?;
        std::io::Write::write_all(&mut file, b"\n")?;
        file.sync_all()?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o444))?;
        fs::rename(&temporary, marker)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

async fn download_extract_and_verify(
    transport: &str,
    release: &SignedApplianceRelease,
    candidate: &Path,
) -> Result<()> {
    let snapshot = &release.cybex_repository_snapshot;
    let canonical_transport = transport == snapshot.url;
    let mut response = release_transport::get(
        transport,
        !canonical_transport,
        canonical_transport,
        Duration::from_secs(4 * 60 * 60),
        None,
    )
    .await
    .context("download appliance package snapshot")?;
    if response.status() != StatusCode::OK
        || response
            .content_length()
            .is_some_and(|length| length != snapshot.size_bytes)
        || response
            .headers()
            .get(header::CONTENT_ENCODING)
            .is_some_and(|value| value.as_bytes() != b"identity")
    {
        bail!("appliance package snapshot response is invalid")
    }

    let (mut writer, reader) = tokio::io::duplex(1024 * 1024);
    let extraction_root = candidate.to_path_buf();
    let extraction = tokio::task::spawn_blocking(move || {
        extract_snapshot_reader(
            SyncIoBridge::new(reader),
            &extraction_root,
            MAX_EXPANDED_BYTES,
        )
    });
    let mut hasher = Sha256::new();
    let mut received = 0u64;
    let mut stream_error = None;
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                received = match received.checked_add(chunk.len() as u64) {
                    Some(received) if received <= snapshot.size_bytes => received,
                    _ => {
                        stream_error = Some(anyhow!(
                            "appliance package snapshot exceeded its signed size"
                        ));
                        break;
                    }
                };
                hasher.update(&chunk);
                if let Err(error) = writer.write_all(&chunk).await {
                    stream_error = Some(error.into());
                    break;
                }
            }
            Ok(None) => break,
            Err(error) => {
                stream_error = Some(error.into());
                break;
            }
        }
    }
    drop(writer);
    let extraction_result = extraction
        .await
        .context("join appliance package extraction")?;
    if let Err(error) = extraction_result {
        return Err(error).context("extract appliance package snapshot");
    }
    if let Some(error) = stream_error {
        return Err(error).context("stream appliance package snapshot");
    }
    if received != snapshot.size_bytes || hex::encode(hasher.finalize()) != snapshot.sha256 {
        bail!("appliance package snapshot integrity check failed")
    }
    verify_thin_installer_snapshot(candidate, release)
}

fn validate_transport_url(transport: &str, release: &SignedApplianceRelease) -> Result<Url> {
    if transport.is_empty() || transport.trim() != transport || transport.len() > 4096 {
        bail!("appliance package transport URL is invalid")
    }
    let parsed = Url::parse(transport).context("parse appliance package transport URL")?;
    if parsed.as_str() != transport
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        bail!("appliance package transport URL is not canonical")
    }
    let canonical = &release.cybex_repository_snapshot.url;
    if transport == canonical {
        if parsed.scheme() != "https" {
            bail!("canonical appliance package transport must use HTTPS")
        }
        return Ok(parsed);
    }
    let expected_filename = format!(
        "cybex-james-appliance-packages-{}-x86_64-linux.tar.zst",
        release.release_id
    );
    let private_address = parsed
        .host_str()
        .and_then(|host| host.trim_matches(['[', ']']).parse::<IpAddr>().ok())
        .is_some_and(|address| match address {
            IpAddr::V4(address) => address.is_private() || address.is_loopback(),
            IpAddr::V6(address) => address.is_unique_local() || address.is_loopback(),
        });
    if parsed.scheme() != "http"
        || !private_address
        || parsed.port().is_none()
        || parsed
            .path_segments()
            .and_then(|mut segments| segments.next_back())
            != Some(expected_filename.as_str())
    {
        bail!("qualification package transport URL is not an explicit private HTTP endpoint")
    }
    Ok(parsed)
}

fn ensure_staging_directory(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => bail!("volatile appliance repository root is unsafe"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(path).context("create volatile appliance repository root")?;
        }
        Err(error) => return Err(error).context("inspect volatile appliance repository root"),
    }
    // APT drops privileges to `_apt` while reading file:// repositories. The
    // staged bytes are public, independently signed release artifacts; keep
    // the directory non-writable while allowing that sandbox user to traverse
    // to the already-verified, read-only repository.
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
    Ok(())
}

fn ensure_tmpfs_capacity(path: &Path, required_bytes: u64) -> Result<()> {
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| anyhow!("volatile appliance repository path contains NUL"))?;
    let mut stats = std::mem::MaybeUninit::<libc::statfs>::zeroed();
    if unsafe { libc::statfs(path.as_ptr(), stats.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error()).context("inspect volatile tmpfs");
    }
    let stats = unsafe { stats.assume_init() };
    validate_tmpfs_capacity(
        stats.f_type,
        stats.f_bsize as u64,
        stats.f_bavail,
        required_bytes,
    )
}

fn validate_tmpfs_capacity(
    filesystem_type: i64,
    block_size: u64,
    available_blocks: u64,
    required_bytes: u64,
) -> Result<()> {
    if filesystem_type != TMPFS_MAGIC {
        bail!("appliance package staging root is not backed by tmpfs")
    }
    let available = block_size
        .checked_mul(available_blocks)
        .ok_or_else(|| anyhow!("volatile appliance repository capacity overflow"))?;
    if available < required_bytes {
        bail!("tmpfs has insufficient capacity for the approved appliance repository")
    }
    Ok(())
}

fn required_staging_capacity(release: &SignedApplianceRelease) -> Result<u64> {
    let bundle = release.cybex_repository_snapshot.size_bytes;
    if bundle > MAX_SNAPSHOT_BYTES {
        bail!("approved appliance repository exceeds its compressed size bound")
    }
    Ok(bundle
        .checked_add((bundle / 8).max(MINIMUM_TMPFS_HEADROOM))
        .unwrap_or(u64::MAX)
        .min(MAX_EXPANDED_BYTES))
}

fn remove_stale_candidates(root: &Path) -> Result<()> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            bail!("volatile appliance repository contains an invalid entry")
        };
        if name.starts_with(".packages.") {
            let metadata = entry.file_type()?;
            if !metadata.is_dir() {
                bail!("volatile appliance repository candidate is unsafe")
            }
            fs::remove_dir_all(entry.path())?;
        } else if name.starts_with(".verified-snapshot.") && name.ends_with(".tmp") {
            if !entry.file_type()?.is_file() {
                bail!("volatile appliance repository marker candidate is unsafe")
            }
            fs::remove_file(entry.path())?;
        } else if name != "packages" {
            bail!("volatile appliance repository contains an unexpected entry")
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn release(canonical_url: &str) -> SignedApplianceRelease {
        SignedApplianceRelease {
            schema: "cybex.james.appliance-release.v1".into(),
            release_id: "0.1.2".into(),
            source_revision: None,
            ubuntu_snapshot_id: "20260801T120000Z".into(),
            cybex_repository_snapshot: crate::appliance::ApplianceRepositorySnapshot {
                url: canonical_url.into(),
                sha256: "a".repeat(64),
                size_bytes: 1024 * 1024 * 1024,
            },
            required_package_versions: BTreeMap::new(),
            expected_kernel: String::new(),
            minimum_protocol: 4,
            minimum_state_schema: 2,
            rollback_compatible: true,
            release_notes: "https://releases.cybex.net/0.1.2".into(),
            signature: String::new(),
        }
    }

    #[test]
    fn production_transport_must_equal_the_release_signed_https_url() {
        let url =
            "https://releases.cybex.net/cybex-james-appliance-packages-0.1.2-x86_64-linux.tar.zst";
        assert!(validate_transport_url(url, &release(url)).is_ok());
        assert!(
            validate_transport_url(
                "https://mirror.example/cybex-james-appliance-packages-0.1.2-x86_64-linux.tar.zst",
                &release(url)
            )
            .is_err()
        );
    }

    #[test]
    fn qualification_transport_is_an_explicit_private_ip_endpoint() {
        let release = release(
            "https://releases.cybex.net/cybex-james-appliance-packages-0.1.2-x86_64-linux.tar.zst",
        );
        assert!(
            validate_transport_url(
                "http://192.168.122.1:8080/cybex-james-appliance-packages-0.1.2-x86_64-linux.tar.zst",
                &release
            )
            .is_ok()
        );
        assert!(
            validate_transport_url(
                "http://[fd00::1]:8080/cybex-james-appliance-packages-0.1.2-x86_64-linux.tar.zst",
                &release
            )
            .is_ok()
        );
        for invalid in [
            "http://example.test:8080/cybex-james-appliance-packages-0.1.2-x86_64-linux.tar.zst",
            "http://203.0.113.2:8080/cybex-james-appliance-packages-0.1.2-x86_64-linux.tar.zst",
            "http://127.0.0.1/cybex-james-appliance-packages-0.1.2-x86_64-linux.tar.zst",
            "http://127.0.0.1:8080/wrong.tar.zst",
            "http://user@127.0.0.1:8080/cybex-james-appliance-packages-0.1.2-x86_64-linux.tar.zst",
            "http://127.0.0.1:8080/cybex-james-appliance-packages-0.1.2-x86_64-linux.tar.zst?token=x",
        ] {
            assert!(
                validate_transport_url(invalid, &release).is_err(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn tmpfs_type_and_capacity_are_both_required() {
        assert!(validate_tmpfs_capacity(TMPFS_MAGIC, 4096, 1024, 4096).is_ok());
        assert!(validate_tmpfs_capacity(0xef53, 4096, 1024, 4096).is_err());
        assert!(validate_tmpfs_capacity(TMPFS_MAGIC, 4096, 1, 4097).is_err());
    }

    #[test]
    fn staging_capacity_keeps_headroom_without_exceeding_expansion_cap() {
        let release = release(
            "https://releases.cybex.net/cybex-james-appliance-packages-0.1.2-x86_64-linux.tar.zst",
        );
        assert_eq!(
            required_staging_capacity(&release).unwrap(),
            1024 * 1024 * 1024 + 128 * 1024 * 1024
        );
        let mut oversized = release;
        oversized.cybex_repository_snapshot.size_bytes = MAX_EXPANDED_BYTES;
        assert_eq!(
            required_staging_capacity(&oversized).unwrap(),
            MAX_EXPANDED_BYTES
        );
        oversized.cybex_repository_snapshot.size_bytes += 1;
        assert!(required_staging_capacity(&oversized).is_err());
    }
}
