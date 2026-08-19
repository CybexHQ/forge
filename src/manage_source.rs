use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MANAGE_SOURCE_URL_TEMPLATE: &str =
    "tarball+file:///usr/share/cybex-james/manage-source/{revision}.tar";
pub const MANAGE_SOURCE_METADATA_SCHEMA: &str = "cybex.james.manage-source.v1";
const MAX_METADATA_BYTES: u64 = 16 * 1024;
const MAX_ARCHIVE_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ManageSourceMetadata {
    // Keep fields in lexical order. The package builder emits canonical
    // compact sorted JSON and this order makes the byte comparison explicit.
    filename: String,
    revision: String,
    schema: String,
    sha256: String,
    size_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedManageSource {
    pub url: String,
    pub sha256: String,
    pub size_bytes: u64,
}

pub fn normalize_url_template(value: &str, allow_private_fixture: bool) -> Result<String> {
    let value = value.trim();
    if value == MANAGE_SOURCE_URL_TEMPLATE {
        return Ok(value.to_string());
    }
    if !allow_private_fixture {
        bail!("build.manage_source_url_template must use the packaged Manage source archive");
    }
    let path = archive_path_from_template(value, &"0".repeat(40))?;
    if path.file_name().and_then(|name| name.to_str()) != Some(&format!("{}.tar", "0".repeat(40))) {
        bail!("build.manage_source_url_template must end in {{revision}}.tar");
    }
    Ok(value.to_string())
}

pub fn verify_revision(
    template: &str,
    revision: &str,
    allow_private_fixture: bool,
) -> Result<VerifiedManageSource> {
    validate_revision(revision)?;
    let template = normalize_url_template(template, allow_private_fixture)?;
    let archive_path = archive_path_from_template(&template, revision)?;
    let expected_filename = format!("{revision}.tar");
    if archive_path.file_name().and_then(|name| name.to_str()) != Some(&expected_filename) {
        bail!("packaged Manage source archive filename does not match its revision");
    }
    let metadata_path = archive_path.with_extension("json");
    // The allow flag permits a service-owned development fixture, but it must
    // not weaken or change the ownership contract of the canonical packaged
    // archive. Package-managed source remains immutable and root-owned even
    // when other private development release URLs are enabled.
    let (owner_uid, owner_gid) = if is_private_fixture_template(&template) {
        unsafe { (libc::geteuid(), libc::getegid()) }
    } else {
        (0, 0)
    };
    verify_parent_directory(
        archive_path
            .parent()
            .ok_or_else(|| anyhow!("packaged Manage source archive has no parent directory"))?,
        owner_uid,
        owner_gid,
    )?;

    let mut metadata_file =
        open_verified_file(&metadata_path, owner_uid, owner_gid, MAX_METADATA_BYTES)?;
    let mut metadata_body = Vec::new();
    metadata_file
        .by_ref()
        .take(MAX_METADATA_BYTES + 1)
        .read_to_end(&mut metadata_body)
        .context("read packaged Manage source metadata")?;
    if metadata_body.is_empty() || metadata_body.len() as u64 > MAX_METADATA_BYTES {
        bail!("packaged Manage source metadata size is outside its bound");
    }
    let metadata: ManageSourceMetadata =
        serde_json::from_slice(&metadata_body).context("parse packaged Manage source metadata")?;
    let mut canonical =
        serde_json::to_vec(&metadata).context("serialize packaged Manage source metadata")?;
    canonical.push(b'\n');
    if canonical != metadata_body {
        bail!("packaged Manage source metadata is not canonical compact sorted JSON");
    }
    if metadata.schema != MANAGE_SOURCE_METADATA_SCHEMA
        || metadata.revision != revision
        || metadata.filename != expected_filename
        || !is_sha256(&metadata.sha256)
        || metadata.size_bytes == 0
        || metadata.size_bytes > MAX_ARCHIVE_BYTES
    {
        bail!("packaged Manage source metadata does not match the requested revision");
    }

    let mut archive = open_verified_file(&archive_path, owner_uid, owner_gid, MAX_ARCHIVE_BYTES)?;
    let archive_size = archive
        .metadata()
        .context("inspect packaged Manage source archive")?
        .len();
    if archive_size != metadata.size_bytes {
        bail!("packaged Manage source archive size does not match its metadata");
    }
    let mut hasher = Sha256::new();
    let copied =
        std::io::copy(&mut archive, &mut hasher).context("hash packaged Manage source archive")?;
    if copied != metadata.size_bytes || hex::encode(hasher.finalize()) != metadata.sha256 {
        bail!("packaged Manage source archive SHA-256 does not match its metadata");
    }

    Ok(VerifiedManageSource {
        url: template.replace("{revision}", revision),
        sha256: metadata.sha256,
        size_bytes: metadata.size_bytes,
    })
}

fn archive_path_from_template(template: &str, revision: &str) -> Result<PathBuf> {
    if template.len() > 4096
        || template.chars().any(char::is_control)
        || template.matches("{revision}").count() != 1
        || !template.starts_with("tarball+file:///")
        || template.contains('?')
        || template.contains('#')
        || template.contains('%')
    {
        bail!(
            "build.manage_source_url_template must be an absolute credential-free tarball+file URL with one {{revision}} placeholder"
        );
    }
    let expanded = template.replace("{revision}", revision);
    let path_text = expanded
        .strip_prefix("tarball+file://")
        .expect("validated tarball file URL");
    if path_text[1..].contains("//") || path_text.ends_with('/') {
        bail!("build.manage_source_url_template path is not canonical and absolute");
    }
    let path = PathBuf::from(path_text);
    if !path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        bail!("build.manage_source_url_template path is not canonical and absolute");
    }
    Ok(path)
}

fn validate_revision(revision: &str) -> Result<()> {
    if revision.len() != 40
        || !revision
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("packaged Manage source revision must be exact lowercase 40-hex");
    }
    Ok(())
}

fn is_private_fixture_template(template: &str) -> bool {
    template != MANAGE_SOURCE_URL_TEMPLATE
}

fn verify_parent_directory(path: &Path, owner_uid: u32, owner_gid: u32) -> Result<()> {
    let metadata = fs::symlink_metadata(path).with_context(|| {
        format!(
            "inspect packaged Manage source directory {}",
            path.display()
        )
    })?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != owner_uid
        || metadata.gid() != owner_gid
        || metadata.permissions().mode() & 0o777 != 0o755
    {
        bail!("packaged Manage source directory metadata is unsafe");
    }
    Ok(())
}

fn open_verified_file(
    path: &Path,
    owner_uid: u32,
    owner_gid: u32,
    maximum_size: u64,
) -> Result<File> {
    let link_metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect packaged Manage source file {}", path.display()))?;
    if !link_metadata.file_type().is_file()
        || link_metadata.uid() != owner_uid
        || link_metadata.gid() != owner_gid
        || link_metadata.nlink() != 1
        || link_metadata.permissions().mode() & 0o777 != 0o444
        || link_metadata.len() == 0
        || link_metadata.len() > maximum_size
    {
        bail!("packaged Manage source file metadata is unsafe");
    }
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let file = options
        .open(path)
        .with_context(|| format!("open packaged Manage source file {}", path.display()))?;
    let opened = file
        .metadata()
        .with_context(|| format!("inspect opened Manage source file {}", path.display()))?;
    if opened.dev() != link_metadata.dev()
        || opened.ino() != link_metadata.ino()
        || opened.uid() != owner_uid
        || opened.gid() != owner_gid
        || opened.nlink() != 1
        || opened.permissions().mode() & 0o777 != 0o444
        || opened.len() != link_metadata.len()
    {
        bail!("packaged Manage source file changed while it was opened");
    }
    Ok(file)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn fixture() -> (PathBuf, String, String) {
        let revision = "a".repeat(40);
        let root = std::env::temp_dir().join(format!(
            "cybex-james-manage-source-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        let archive = root.join(format!("{revision}.tar"));
        let body = b"deterministic Manage source archive";
        fs::write(&archive, body).unwrap();
        fs::set_permissions(&archive, fs::Permissions::from_mode(0o444)).unwrap();
        let metadata = ManageSourceMetadata {
            filename: format!("{revision}.tar"),
            revision: revision.clone(),
            schema: MANAGE_SOURCE_METADATA_SCHEMA.to_string(),
            sha256: hex::encode(Sha256::digest(body)),
            size_bytes: body.len() as u64,
        };
        let metadata_path = root.join(format!("{revision}.json"));
        let mut file = File::create(&metadata_path).unwrap();
        serde_json::to_writer(&mut file, &metadata).unwrap();
        file.write_all(b"\n").unwrap();
        drop(file);
        fs::set_permissions(&metadata_path, fs::Permissions::from_mode(0o444)).unwrap();
        let template = format!("tarball+file://{}/{{revision}}.tar", root.display());
        (root, revision, template)
    }

    #[test]
    fn verifies_exact_local_archive_and_metadata() {
        let (root, revision, template) = fixture();
        let verified = verify_revision(&template, &revision, true).unwrap();
        assert_eq!(verified.url, template.replace("{revision}", &revision));
        assert_eq!(verified.size_bytes, 35);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_corrupt_or_writable_packaged_source() {
        let (root, revision, template) = fixture();
        let archive = root.join(format!("{revision}.tar"));
        fs::set_permissions(&archive, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            verify_revision(&template, &revision, true)
                .unwrap_err()
                .to_string()
                .contains("metadata is unsafe")
        );
        fs::set_permissions(&archive, fs::Permissions::from_mode(0o444)).unwrap();
        fs::set_permissions(&archive, fs::Permissions::from_mode(0o644)).unwrap();
        fs::write(&archive, b"different bytes").unwrap();
        fs::set_permissions(&archive, fs::Permissions::from_mode(0o444)).unwrap();
        assert!(
            verify_revision(&template, &revision, true)
                .unwrap_err()
                .to_string()
                .contains("size does not match")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn rejects_hardlinked_or_symlinked_packaged_source() {
        use std::os::unix::fs::symlink;

        let (root, revision, template) = fixture();
        let archive = root.join(format!("{revision}.tar"));
        let second_link = root.join("second-link.tar");
        fs::hard_link(&archive, &second_link).unwrap();
        assert!(
            verify_revision(&template, &revision, true)
                .unwrap_err()
                .to_string()
                .contains("metadata is unsafe")
        );
        fs::remove_file(second_link).unwrap();
        fs::remove_file(&archive).unwrap();
        symlink("missing-target", &archive).unwrap();
        assert!(
            verify_revision(&template, &revision, true)
                .unwrap_err()
                .to_string()
                .contains("metadata is unsafe")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn production_template_is_fixed_to_package_storage() {
        assert_eq!(
            normalize_url_template(MANAGE_SOURCE_URL_TEMPLATE, false).unwrap(),
            MANAGE_SOURCE_URL_TEMPLATE
        );
        assert!(normalize_url_template("github:CybexHQ/manage/{revision}", false).is_err());
    }

    #[test]
    fn private_fixture_permission_does_not_change_canonical_package_ownership() {
        let normalized = normalize_url_template(MANAGE_SOURCE_URL_TEMPLATE, true).unwrap();
        assert_eq!(normalized, MANAGE_SOURCE_URL_TEMPLATE);
        assert!(!is_private_fixture_template(&normalized));

        let private = "tarball+file:///tmp/cybex-james-test/{revision}.tar";
        assert!(is_private_fixture_template(
            &normalize_url_template(private, true).unwrap()
        ));
    }
}
