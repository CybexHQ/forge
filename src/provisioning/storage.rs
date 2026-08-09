use super::{
    DurableProvisioningState,
    inventory::PulseProvisioningInventory,
    packages::{PackageDelivery, STAGED_REPOSITORY_PATH},
    protocol::{PulseProvisioningNetworkPlan, SignedInstallPlan},
};
use anyhow::{Context, Result, anyhow, bail};
use chrono::Utc;
use serde_json::{Value, json};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::{
        ffi::OsStrExt,
        fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::Command as StdCommand,
};
use tokio::process::Command;
use uuid::Uuid;

const GIB: u64 = 1024 * 1024 * 1024;
const EFI_BYTES: u64 = GIB;
const ROOT_BYTES: u64 = 48 * GIB;
const STATE_BYTES: u64 = 16 * GIB;
const SWAP_BYTES: u64 = 8 * GIB;
const EXT4_SUPER_MAGIC: i64 = 0xef53;

#[derive(Clone, Debug)]
pub(crate) struct PreparedStorage {
    pub disk_path: PathBuf,
    pub state_mount: PathBuf,
    sector_size: u64,
    partition_starts: [u64; 5],
    partition_ends: [u64; 5],
}

#[derive(Clone, Debug)]
pub(crate) struct ExistingStateProbe {
    pub state: DurableProvisioningState,
    device_path: PathBuf,
    requires_rw_mount: bool,
}

pub(crate) fn existing_state_for_session(
    state_mount: &Path,
    session_id: Uuid,
) -> Result<Option<ExistingStateProbe>> {
    let Some(device_path) = existing_state_device()? else {
        if DurableProvisioningState::path(state_mount).exists() {
            bail!("mounted CYBEX_STATE has no unique partition-label device")
        }
        return Ok(None);
    };
    let state_path = DurableProvisioningState::path(state_mount);
    let requires_rw_mount = if state_path.exists() {
        validate_state_mount(state_mount, &device_path)?;
        validate_existing_recovery_probe(state_mount)?;
        true
    } else {
        mount_existing_state_probe(state_mount, &device_path)?;
        true
    };
    if !state_path.exists() {
        bail!("CYBEX_STATE does not contain durable provisioning state")
    }
    let state = load_durable_state(state_mount)?;
    if state.session_id == session_id {
        if state.installation_complete {
            boot_installed_appliance()?;
            bail!("completed appliance reboot command unexpectedly returned")
        }
        return Ok(Some(ExistingStateProbe {
            state,
            device_path,
            requires_rw_mount,
        }));
    }
    bail!("an existing CYBEX_STATE identity belongs to different provisioning media")
}

fn existing_state_device() -> Result<Option<PathBuf>> {
    let mut candidates = fs::read_dir("/dev/disk/by-partlabel")
        .ok()
        .into_iter()
        .flatten()
        .flatten()
        .filter(|entry| entry.file_name() == "CYBEX_STATE")
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    candidates.sort();
    if candidates.is_empty() {
        return Ok(None);
    }
    if candidates.len() != 1 {
        bail!("multiple CYBEX_STATE partitions are present; detach unrelated appliance disks")
    }
    Ok(candidates.pop())
}

fn mount_existing_state_probe(state_mount: &Path, device_path: &Path) -> Result<()> {
    fs::create_dir_all(state_mount).context("create existing state mountpoint")?;
    let status = StdCommand::new("mount")
        .args(["-t", "ext4", "-o", recovery_probe_mount_options()])
        .arg(device_path)
        .arg(state_mount)
        .status()
        .context("mount existing CYBEX_STATE recovery probe")?;
    if !status.success() {
        bail!("existing CYBEX_STATE could not be mounted read-only without journal replay")
    }
    validate_state_mount(state_mount, device_path)?;
    validate_existing_recovery_probe(state_mount)?;
    Ok(())
}

pub(crate) fn activate_existing_state(
    state_mount: &Path,
    probe: &ExistingStateProbe,
) -> Result<DurableProvisioningState> {
    if probe.requires_rw_mount {
        let status = StdCommand::new("umount")
            .arg(state_mount)
            .status()
            .context("unmount read-only CYBEX_STATE recovery probe")?;
        if !status.success() {
            bail!("read-only CYBEX_STATE recovery probe could not be unmounted")
        }
        let status = StdCommand::new("mount")
            .args(["-t", "ext4", "-o", recovery_active_mount_options()])
            .arg(&probe.device_path)
            .arg(state_mount)
            .status()
            .context("mount active CYBEX_STATE recovery state")?;
        if !status.success() {
            bail!("CYBEX_STATE could not be activated after package verification")
        }
    }
    validate_state_mount(state_mount, &probe.device_path)?;
    if mount_is_read_only(state_mount)? {
        bail!("active CYBEX_STATE recovery mount remained read-only")
    }
    let refreshed = load_durable_state(state_mount)?;
    validate_recovered_state_transition(&probe.state, &refreshed)?;
    if refreshed.installation_complete {
        boot_installed_appliance()?;
        bail!("completed appliance reboot command unexpectedly returned")
    }
    Ok(refreshed)
}

fn recovery_probe_mount_options() -> &'static str {
    "ro,noload,nodev,nosuid"
}

fn recovery_active_mount_options() -> &'static str {
    "rw,nodev,nosuid"
}

fn require_read_only_recovery_probe(read_only: bool) -> Result<()> {
    if !read_only {
        bail!("refusing recovery while CYBEX_STATE is writable; reboot to obtain a read-only probe")
    }
    Ok(())
}

fn validate_existing_recovery_probe(path: &Path) -> Result<()> {
    require_read_only_recovery_probe(mount_is_read_only(path)?)?;
    let mountinfo = fs::read("/proc/self/mountinfo").context("read recovery mount metadata")?;
    if mountinfo.len() > 4 * 1024 * 1024
        || !mountinfo_has_safe_recovery_probe(&mountinfo, path.as_os_str().as_bytes())
    {
        bail!("CYBEX_STATE recovery probe did not disable ext4 journal replay")
    }
    Ok(())
}

fn mountinfo_has_safe_recovery_probe(mountinfo: &[u8], mount_path: &[u8]) -> bool {
    let escaped_path = escape_mountinfo_path(mount_path);
    mountinfo.split(|byte| *byte == b'\n').any(|line| {
        let fields = line
            .split(|byte| *byte == b' ')
            .filter(|field| !field.is_empty())
            .collect::<Vec<_>>();
        let Some(separator) = fields.iter().position(|field| *field == b"-") else {
            return false;
        };
        if fields.len() <= separator + 3
            || fields.get(4).copied() != Some(escaped_path.as_slice())
            || fields.get(separator + 1).copied() != Some(b"ext4")
        {
            return false;
        }
        let mount_options = fields[5];
        let super_options = fields[separator + 3];
        comma_option(mount_options, b"ro")
            && (comma_option(mount_options, b"noload")
                || comma_option(mount_options, b"norecovery")
                || comma_option(super_options, b"noload")
                || comma_option(super_options, b"norecovery"))
    })
}

fn escape_mountinfo_path(path: &[u8]) -> Vec<u8> {
    let mut escaped = Vec::with_capacity(path.len());
    for byte in path {
        match byte {
            b' ' => escaped.extend_from_slice(b"\\040"),
            b'\t' => escaped.extend_from_slice(b"\\011"),
            b'\n' => escaped.extend_from_slice(b"\\012"),
            b'\\' => escaped.extend_from_slice(b"\\134"),
            byte => escaped.push(*byte),
        }
    }
    escaped
}

fn comma_option(options: &[u8], expected: &[u8]) -> bool {
    options
        .split(|byte| *byte == b',')
        .any(|option| option == expected)
}

fn mount_is_read_only(path: &Path) -> Result<bool> {
    let path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| anyhow!("CYBEX_STATE mount path contains NUL"))?;
    let mut stats = std::mem::MaybeUninit::<libc::statvfs>::zeroed();
    if unsafe { libc::statvfs(path.as_ptr(), stats.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error()).context("inspect CYBEX_STATE mount flags");
    }
    let stats = unsafe { stats.assume_init() };
    Ok(stats.f_flag & libc::ST_RDONLY as libc::c_ulong != 0)
}

fn mounted_filesystem_type(path: &Path) -> Result<i64> {
    let path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| anyhow!("CYBEX_STATE mount path contains NUL"))?;
    let mut stats = std::mem::MaybeUninit::<libc::statfs>::zeroed();
    if unsafe { libc::statfs(path.as_ptr(), stats.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error()).context("inspect CYBEX_STATE filesystem type");
    }
    Ok(unsafe { stats.assume_init() }.f_type)
}

fn validate_state_mount(state_mount: &Path, device_path: &Path) -> Result<()> {
    let mount = fs::metadata(state_mount).context("inspect CYBEX_STATE mountpoint")?;
    let device = fs::metadata(device_path).context("inspect CYBEX_STATE block device")?;
    if !mount.is_dir()
        || !device.file_type().is_block_device()
        || mounted_filesystem_type(state_mount)? != EXT4_SUPER_MAGIC
        || libc::major(mount.dev()) != libc::major(device.rdev())
        || libc::minor(mount.dev()) != libc::minor(device.rdev())
    {
        bail!("CYBEX_STATE mount does not match its unique partition-label device")
    }
    Ok(())
}

fn validate_recovered_state_transition(
    probed: &DurableProvisioningState,
    active: &DurableProvisioningState,
) -> Result<()> {
    if active.schema != probed.schema
        || active.session_id != probed.session_id
        || serde_json::to_vec(&active.plan)? != serde_json::to_vec(&probed.plan)?
        || active.manage_origin != probed.manage_origin
        || active.management_signing_public_key_b64 != probed.management_signing_public_key_b64
        || active.device_private_key_b64 != probed.device_private_key_b64
        || active.device_public_key_b64 != probed.device_public_key_b64
        || active.device_public_key_fingerprint != probed.device_public_key_fingerprint
        || active.next_event_sequence < probed.next_event_sequence
        || active.next_event_sequence > if active.installation_complete { 9 } else { 6 }
        || (probed.identity_active && !active.identity_active)
        || (probed.installation_complete && !active.installation_complete)
        || active.updated_at < probed.updated_at
    {
        bail!("CYBEX_STATE changed incompatibly while its recovery probe was read-only")
    }
    Ok(())
}

fn boot_installed_appliance() -> Result<()> {
    let output = StdCommand::new("efibootmgr")
        .output()
        .context("inspect UEFI boot entries")?;
    if !output.status.success() || output.stdout.len() > 64 * 1024 {
        bail!("installed appliance boot entry is unavailable")
    }
    let body = String::from_utf8(output.stdout).context("UEFI boot entries are not UTF-8")?;
    let boot_number = body.lines().find_map(|line| {
        let lower = line.to_ascii_lowercase();
        if !(lower.contains("ubuntu") || lower.contains("cybex pulse"))
            || !line.starts_with("Boot")
            || line.len() < 8
        {
            return None;
        }
        let number = &line[4..8];
        number
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
            .then_some(number.to_string())
    });
    let number = boot_number.ok_or_else(|| anyhow!("installed appliance boot entry is missing"))?;
    let status = StdCommand::new("efibootmgr")
        .args(["--bootnext", &number])
        .status()
        .context("select installed appliance for next boot")?;
    if !status.success() {
        bail!("could not select installed appliance for next boot")
    }
    let _ = StdCommand::new("sync").status();
    let status = StdCommand::new("systemctl")
        .args(["reboot", "--no-block"])
        .status()
        .context("reboot into installed appliance")?;
    if !status.success() {
        bail!("could not reboot into installed appliance")
    }
    std::thread::sleep(std::time::Duration::from_secs(30));
    Ok(())
}

pub(crate) async fn create_state_partition_first(
    plan: &SignedInstallPlan,
    inventory: &PulseProvisioningInventory,
    state_mount: &Path,
) -> Result<PreparedStorage> {
    let disk = inventory
        .disks
        .iter()
        .find(|disk| disk.id == plan.target_disk_id)
        .ok_or_else(|| anyhow!("approved target disk disappeared"))?;
    if disk != &plan.target_disk || !disk.eligible || disk.removable || disk.mounted || disk.held {
        bail!("approved disk changed immediately before partitioning")
    }
    let disk_path = PathBuf::from(&disk.path);
    let metadata = fs::metadata(&disk_path)
        .with_context(|| format!("inspect target disk {}", disk_path.display()))?;
    if !metadata.file_type().is_block_device() || !disk_path.starts_with("/dev") {
        bail!("approved target is not an explicit block device")
    }
    let sector_size = command_u64("blockdev", &["--getss", &disk.path]).await?;
    let total_sectors = command_u64("blockdev", &["--getsz", &disk.path]).await?;
    if !matches!(sector_size, 512 | 4096)
        || total_sectors.checked_mul(sector_size).unwrap_or(0) != disk.size_bytes
    {
        bail!("target disk geometry changed after approval")
    }
    let (starts, ends) = calculate_layout(sector_size, total_sectors)?;

    run_checked("sgdisk", &["--zap-all", &disk.path]).await?;
    run_checked(
        "sgdisk",
        &[
            &format!("--new=3:{}:{}", starts[2], ends[2]),
            "--typecode=3:8300",
            "--change-name=3:CYBEX_STATE",
            &disk.path,
        ],
    )
    .await?;
    settle_partitions(&disk.path).await?;
    let state_partition = partition_path(&disk_path, 3)?;
    run_checked(
        "mkfs.ext4",
        &[
            "-F",
            "-L",
            "CYBEX_STATE",
            state_partition
                .to_str()
                .ok_or_else(|| anyhow!("state partition path is not UTF-8"))?,
        ],
    )
    .await?;
    fs::create_dir_all(state_mount).context("create live state mount")?;
    run_checked(
        "mount",
        &[
            "-o",
            "nodev,nosuid",
            state_partition
                .to_str()
                .ok_or_else(|| anyhow!("state partition path is not UTF-8"))?,
            state_mount
                .to_str()
                .ok_or_else(|| anyhow!("state mount path is not UTF-8"))?,
        ],
    )
    .await?;
    Ok(PreparedStorage {
        disk_path,
        state_mount: state_mount.to_path_buf(),
        sector_size,
        partition_starts: starts,
        partition_ends: ends,
    })
}

pub(crate) async fn resume_prepared_storage(
    plan: &SignedInstallPlan,
    inventory: &PulseProvisioningInventory,
    state_mount: &Path,
) -> Result<PreparedStorage> {
    let disk = inventory
        .disks
        .iter()
        .find(|disk| disk.id == plan.target_disk_id)
        .ok_or_else(|| anyhow!("approved target disk disappeared during recovery"))?;
    if disk != &plan.target_disk || disk.removable || disk.held {
        bail!("approved disk identity changed during recovery")
    }
    let disk_path = PathBuf::from(&disk.path);
    let metadata = fs::metadata(&disk_path)
        .with_context(|| format!("inspect recovery disk {}", disk_path.display()))?;
    if !metadata.file_type().is_block_device() || !disk_path.starts_with("/dev") {
        bail!("recovery target is not an explicit block device")
    }
    let sector_size = command_u64("blockdev", &["--getss", &disk.path]).await?;
    let total_sectors = command_u64("blockdev", &["--getsz", &disk.path]).await?;
    if !matches!(sector_size, 512 | 4096)
        || total_sectors.checked_mul(sector_size).unwrap_or(0) != disk.size_bytes
    {
        bail!("target disk geometry changed during recovery")
    }
    let (starts, ends) = calculate_layout(sector_size, total_sectors)?;
    validate_existing_partition(&disk.path, 3, starts[2], ends[2], "8300", "CYBEX_STATE").await?;
    if !DurableProvisioningState::path(state_mount).is_file() {
        bail!("recovery state partition is not mounted at the expected path")
    }
    Ok(PreparedStorage {
        disk_path,
        state_mount: state_mount.to_path_buf(),
        sector_size,
        partition_starts: starts,
        partition_ends: ends,
    })
}

pub(crate) async fn create_remaining_partitions(prepared: &PreparedStorage) -> Result<()> {
    let disk = prepared
        .disk_path
        .to_str()
        .ok_or_else(|| anyhow!("disk path is not UTF-8"))?;
    let starts = prepared.partition_starts;
    let ends = prepared.partition_ends;
    for (index, start, end, type_code, label) in [
        (1, starts[0], ends[0], "ef00", "CYBEX_EFI"),
        (2, starts[1], ends[1], "8300", "CYBEX_ROOT"),
        (4, starts[3], ends[3], "8200", "CYBEX_SWAP"),
        (5, starts[4], ends[4], "8300", "CYBEX_CACHE"),
    ] {
        match inspect_partition(disk, index).await? {
            Some(partition) => {
                partition.validate(start, end, type_code, label)?;
            }
            None => {
                run_checked(
                    "sgdisk",
                    &[
                        &format!("--new={index}:{start}:{end}"),
                        &format!("--typecode={index}:{type_code}"),
                        &format!("--change-name={index}:{label}"),
                        disk,
                    ],
                )
                .await?;
            }
        }
    }
    settle_partitions(disk).await?;
    for (index, start, end, type_code, label) in [
        (1, starts[0], ends[0], "ef00", "CYBEX_EFI"),
        (2, starts[1], ends[1], "8300", "CYBEX_ROOT"),
        (4, starts[3], ends[3], "8200", "CYBEX_SWAP"),
        (5, starts[4], ends[4], "8300", "CYBEX_CACHE"),
    ] {
        validate_existing_partition(disk, index, start, end, type_code, label).await?;
    }
    Ok(())
}

#[derive(Debug)]
struct ExistingPartition {
    first_sector: u64,
    last_sector: u64,
    type_code: String,
    name: String,
}

impl ExistingPartition {
    fn validate(
        &self,
        first_sector: u64,
        last_sector: u64,
        type_code: &str,
        name: &str,
    ) -> Result<()> {
        if self.first_sector != first_sector
            || self.last_sector != last_sector
            || !partition_type_matches(&self.type_code, type_code)
            || self.name != name
        {
            bail!("existing appliance partition does not match the approved layout")
        }
        Ok(())
    }
}

fn partition_type_matches(reported: &str, expected_short_code: &str) -> bool {
    if reported.eq_ignore_ascii_case(expected_short_code) {
        return true;
    }
    let expected_guid = match expected_short_code.to_ascii_lowercase().as_str() {
        "ef00" => "C12A7328-F81F-11D2-BA4B-00A0C93EC93B",
        "8300" => "0FC63DAF-8483-4772-8E79-3D69D8477DE4",
        "8200" => "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F",
        _ => return false,
    };
    reported.eq_ignore_ascii_case(expected_guid)
}

async fn validate_existing_partition(
    disk: &str,
    index: u8,
    first_sector: u64,
    last_sector: u64,
    type_code: &str,
    name: &str,
) -> Result<()> {
    inspect_partition(disk, index)
        .await?
        .ok_or_else(|| anyhow!("required appliance partition {index} is missing"))?
        .validate(first_sector, last_sector, type_code, name)
}

async fn inspect_partition(disk: &str, index: u8) -> Result<Option<ExistingPartition>> {
    let output = Command::new("sgdisk")
        .args([format!("--info={index}"), disk.to_string()])
        .output()
        .await
        .with_context(|| format!("inspect partition {index} on {disk}"))?;
    if !output.status.success() {
        return Ok(None);
    }
    if output.stdout.len() > 64 * 1024 {
        bail!("partition inspection output is too large")
    }
    let body = String::from_utf8(output.stdout).context("partition inspection is not UTF-8")?;
    parse_partition_info(&body, index)
}

fn parse_partition_info(body: &str, index: u8) -> Result<Option<ExistingPartition>> {
    let missing = format!("Partition #{index} does not exist.");
    if body.lines().any(|line| line.trim() == missing) {
        return Ok(None);
    }
    let field = |prefix: &str| {
        body.lines()
            .find_map(|line| line.trim().strip_prefix(prefix).map(str::trim))
    };
    let first_sector = field("First sector:")
        .and_then(|value| value.split_whitespace().next())
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| anyhow!("partition first sector is unavailable"))?;
    let last_sector = field("Last sector:")
        .and_then(|value| value.split_whitespace().next())
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| anyhow!("partition last sector is unavailable"))?;
    let type_code = field("Partition GUID code:")
        .and_then(|value| value.split_whitespace().next())
        .ok_or_else(|| anyhow!("partition type code is unavailable"))?
        .to_string();
    let name = field("Partition name:")
        .unwrap_or_default()
        .trim_matches('\'')
        .to_string();
    Ok(Some(ExistingPartition {
        first_sector,
        last_sector,
        type_code,
        name,
    }))
}

pub(crate) fn save_durable_state(
    state_mount: &Path,
    state: &DurableProvisioningState,
) -> Result<()> {
    fs::create_dir_all(state_mount).context("create CYBEX_STATE mount directory")?;
    let mut state = state.clone();
    state.updated_at = Utc::now();
    let bytes =
        serde_json::to_vec_pretty(&state).context("serialize durable provisioning state")?;
    if bytes.len() > 512 * 1024 {
        bail!("durable provisioning state exceeds its size limit")
    }
    atomic_write(&DurableProvisioningState::path(state_mount), &bytes, 0o600)
}

pub(crate) fn load_durable_state(state_mount: &Path) -> Result<DurableProvisioningState> {
    let path = DurableProvisioningState::path(state_mount);
    let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    if bytes.len() > 512 * 1024 {
        bail!("durable provisioning state exceeds its size limit")
    }
    let state: DurableProvisioningState =
        serde_json::from_slice(&bytes).context("parse durable provisioning state")?;
    if state.schema != "cybex.pulse.provisioning-state.v1" {
        bail!("durable provisioning state schema is unsupported")
    }
    Ok(state)
}

pub(crate) fn write_autoinstall(
    path: &Path,
    prepared: &PreparedStorage,
    plan: &SignedInstallPlan,
    package_delivery: PackageDelivery,
) -> Result<()> {
    configure_live_offline_apt(Path::new("/"), package_delivery)?;
    let hostname = format!("pulse-{}", device_id_suffix(&plan.reserved_device_id));
    let config = json!({
        "autoinstall": {
            "version": 1,
            "interactive-sections": [],
            "locale": "en_US.UTF-8",
            "keyboard": {"layout": "us"},
            "refresh-installer": {"update": false},
            "apt": offline_apt_config(package_delivery),
            "storage": {"config": storage_config(prepared)?},
            "ssh": {"install-server": true, "allow-pw": false},
            "user-data": {
                "hostname": hostname,
                "disable_root": true,
                "users": []
            },
            "late-commands": offline_package_install_commands(package_delivery),
            "shutdown": "reboot"
        }
    });
    let body = serde_json::to_vec_pretty(&config).context("serialize autoinstall plan")?;
    atomic_write(path, &body, 0o600)
}

fn offline_apt_config(package_delivery: PackageDelivery) -> Value {
    let repository = repository_path(package_delivery);
    json!({
        "preserve_sources_list": true,
        "fallback": "offline-install",
        "conf": concat!(
            "Dir::Etc::sourcelist \"/etc/apt/sources.list.d/cybex-appliance.sources\";\n",
            "Dir::Etc::sourceparts \"-\";\n",
            "Acquire::Languages \"none\";\n"
        ),
        "sources": {
            // Curtin treats the map key as the literal filename below
            // /etc/apt/sources.list.d. Keep the deb822 suffix here; APT ignores
            // extensionless source files, and the extracted target needs this
            // repository during its built-in UEFI curthooks.
            "cybex-appliance.sources": {
                // Curtin's Ubuntu 26.04 legacy-to-deb822 converter drops the
                // trusted option. Supply deb822 directly so apt retains the
                // independently verified repository's trust boundary. Curtin
                // requires the Components field even for a flat repository;
                // an explicitly empty value is valid for the exact-path suite.
                "source": format!(
                    "Types: deb\nURIs: file://{repository}\nSuites: ./\nComponents:\nTrusted: yes\n"
                )
            }
        }
    })
}

fn configure_live_offline_apt(root: &Path, package_delivery: PackageDelivery) -> Result<()> {
    let sources_dir = root.join("etc/apt/sources.list.d");
    fs::create_dir_all(&sources_dir)
        .with_context(|| format!("create {}", sources_dir.display()))?;
    for filename in ["cdrom.sources", "ubuntu.sources"] {
        let path = sources_dir.join(filename);
        if path.exists() {
            fs::remove_file(&path).with_context(|| format!("remove {}", path.display()))?;
        }
    }
    let legacy_sources = root.join("etc/apt/sources.list");
    atomic_write(
        &legacy_sources,
        b"# Cybex Pulse installation uses the verified offline package snapshot.\n",
        0o644,
    )?;
    let repository = repository_path(package_delivery);
    let source =
        format!("Types: deb\nURIs: file://{repository}\nSuites: ./\nComponents:\nTrusted: yes\n");
    atomic_write(
        &sources_dir.join("cybex-appliance.sources"),
        source.as_bytes(),
        0o644,
    )
}

fn offline_package_install_commands(package_delivery: PackageDelivery) -> Value {
    let packages = [
        "cybex-pulse",
        "cybex-pulse-bootstrap",
        "cybex-pulse-appliance",
        "linux-generic",
        "linux-firmware",
        "intel-microcode",
        "amd64-microcode",
        "shim-signed",
        "grub-efi-amd64-signed",
        "secureboot-db",
        "nginx-core",
        "tftpd-hpa",
        "ipxe",
        "nix-bin",
        "nix-setup-systemd",
        "openssh-server",
        "btrfs-progs",
        "watchdog",
    ];
    let apt_options = "-o Dir::Etc::sourcelist=/tmp/cybex-offline.list \
                       -o Dir::Etc::sourceparts=- \
                       -o Acquire::Languages=none";
    let (prepare_repository, cleanup_repository) = match package_delivery {
        PackageDelivery::Embedded => (
            "mkdir -p /target/cdrom; mount --bind /cdrom /target/cdrom; ",
            "; umount /target/cdrom",
        ),
        PackageDelivery::NetworkSnapshot => ("", ""),
    };
    let repository = repository_path(package_delivery);
    let install = format!(
        "{prepare_repository}\
         printf '%s\\n' 'deb [trusted=yes] file://{repository} ./' \
         > /target/tmp/cybex-offline.list; \
         chmod 0644 /target/tmp/cybex-offline.list; \
         trap 'rm -f /target/tmp/cybex-offline.list{cleanup_repository}' EXIT; \
         curtin in-target --target=/target -- apt-get {apt_options} update; \
         curtin in-target --target=/target -- env DEBIAN_FRONTEND=noninteractive \
         apt-get {apt_options} install --yes --no-install-recommends {}",
        packages.join(" ")
    );
    json!([
        ["sh", "-ceu", install],
        "/cdrom/cybex/bootstrap/cybex-pulse-bootstrap event --state-mount /run/cybex-state --stage installing_packages --status succeeded --progress-percent 80 --message 'Offline Ubuntu and Cybex packages installed'",
        "/cdrom/cybex/bootstrap/cybex-pulse-bootstrap finalize-target --target /target --state-mount /run/cybex-state",
        "/cdrom/cybex/bootstrap/cybex-pulse-bootstrap event --state-mount /run/cybex-state --stage installing_bootloader --status succeeded --progress-percent 95 --message 'Signed Ubuntu bootloader installed'",
        "/cdrom/cybex/bootstrap/cybex-pulse-bootstrap event --state-mount /run/cybex-state --stage rebooting --status succeeded --progress-percent 99 --message 'Rebooting into the managed appliance'"
    ])
}

fn repository_path(package_delivery: PackageDelivery) -> &'static str {
    match package_delivery {
        PackageDelivery::Embedded => "/cdrom/cybex/apt",
        PackageDelivery::NetworkSnapshot => STAGED_REPOSITORY_PATH,
    }
}

fn storage_config(prepared: &PreparedStorage) -> Result<Value> {
    let disk = prepared
        .disk_path
        .to_str()
        .ok_or_else(|| anyhow!("target disk path is not UTF-8"))?;
    let mut partition_sizes = [0; 5];
    for (index, (&start, &end)) in prepared
        .partition_starts
        .iter()
        .zip(&prepared.partition_ends)
        .enumerate()
    {
        partition_sizes[index] = end
            .checked_sub(start)
            .and_then(|sectors| sectors.checked_add(1))
            .and_then(|sectors| sectors.checked_mul(prepared.sector_size))
            .ok_or_else(|| anyhow!("approved partition size is invalid"))?;
    }
    Ok(json!([
        {"type":"disk","id":"disk0","path":disk,"ptable":"gpt","preserve":true,"wipe":null},
        {"type":"partition","id":"efi-partition","device":"disk0","number":1,"size":partition_sizes[0],"preserve":true,"flag":"boot","grub_device":true},
        {"type":"partition","id":"root-partition","device":"disk0","number":2,"size":partition_sizes[1],"preserve":true},
        {"type":"partition","id":"state-partition","device":"disk0","number":3,"size":partition_sizes[2],"preserve":true},
        {"type":"partition","id":"swap-partition","device":"disk0","number":4,"size":partition_sizes[3],"preserve":true},
        {"type":"partition","id":"cache-partition","device":"disk0","number":5,"size":partition_sizes[4],"preserve":true},
        {"type":"format","id":"efi-format","volume":"efi-partition","fstype":"fat32","label":"CYBEX_EFI"},
        {"type":"format","id":"root-format","volume":"root-partition","fstype":"btrfs","label":"CYBEX_ROOT"},
        {"type":"format","id":"state-format","volume":"state-partition","fstype":"ext4","label":"CYBEX_STATE","preserve":true},
        {"type":"format","id":"swap-format","volume":"swap-partition","fstype":"swap","label":"CYBEX_SWAP"},
        {"type":"format","id":"cache-format","volume":"cache-partition","fstype":"ext4","label":"CYBEX_CACHE"},
        {"type":"mount","id":"root-mount","device":"root-format","path":"/","options":"defaults"},
        {"type":"mount","id":"efi-mount","device":"efi-format","path":"/boot/efi","options":"umask=0077"},
        {"type":"mount","id":"state-mount","device":"state-format","path":"/var/lib/cybex-pulse/state","options":"nodev,nosuid"},
        {"type":"mount","id":"cache-mount","device":"cache-format","path":"/var/cache/cybex-pulse","options":"nodev,nosuid,exec"},
        {"type":"mount","id":"swap-mount","device":"swap-format","path":"none"}
    ]))
}

pub(crate) fn materialize_target(
    target: &Path,
    state_mount: &Path,
    state: &DurableProvisioningState,
) -> Result<()> {
    if !target.is_absolute() || target == Path::new("/") {
        bail!("installed target must be an explicit non-root absolute path")
    }
    if state.plan.ssh_ca_public_keys.is_empty() {
        bail!("install plan contains no SSH CA trust key")
    }
    let target_state = target.join("var/lib/cybex-pulse/state");
    let target_etc = target.join("etc/cybex-pulse");
    let target_ssh = target.join("etc/ssh");
    let target_netplan = target.join("etc/netplan");
    for directory in [&target_state, &target_etc, &target_ssh, &target_netplan] {
        fs::create_dir_all(directory).with_context(|| format!("create {}", directory.display()))?;
    }
    let transient_apt_source = target.join("etc/apt/sources.list.d/cybex-appliance.sources");
    if transient_apt_source.exists() {
        fs::remove_file(&transient_apt_source)
            .with_context(|| format!("remove {}", transient_apt_source.display()))?;
    }

    let managed_state = json!({
        "private_key_b64": state.device_private_key_b64,
        "public_key_b64": state.device_public_key_b64,
        "public_key_fingerprint": state.device_public_key_fingerprint,
        "device_id": state.plan.reserved_device_id,
        "last_reported_event_id": null
    });
    atomic_write(
        &target_state.join("manage-state.json"),
        &serde_json::to_vec_pretty(&managed_state)?,
        0o600,
    )?;
    atomic_write(
        &target_state.join("install-plan.json"),
        &serde_json::to_vec_pretty(&state.plan)?,
        0o600,
    )?;

    let public_base_url = public_base_url(&state.plan);
    let config = pulse_config(target, state, &public_base_url)?;
    atomic_write(&target_etc.join("config.toml"), config.as_bytes(), 0o600)?;
    atomic_write(
        &target_netplan.join("90-cybex-pulse.yaml"),
        &serde_json::to_vec_pretty(&netplan(&state.plan.network, &state.plan))?,
        0o600,
    )?;
    atomic_write(
        &target_state.join("netplan-approved.json"),
        &serde_json::to_vec_pretty(&netplan(&state.plan.network, &state.plan))?,
        0o600,
    )?;
    let fallback = PulseProvisioningNetworkPlan {
        mode: "dhcp".to_string(),
        interface_id: state.plan.network.interface_id.clone(),
        address_cidr: None,
        gateway: None,
        dns_servers: Vec::new(),
    };
    atomic_write(
        &target_state.join("netplan-dhcp-fallback.json"),
        &serde_json::to_vec_pretty(&netplan(&fallback, &state.plan))?,
        0o600,
    )?;
    atomic_write(
        &target_ssh.join("cybex-pulse-ca.pub"),
        format!("{}\n", state.plan.ssh_ca_public_keys.join("\n")).as_bytes(),
        0o644,
    )?;
    atomic_write(
        &target_ssh.join("cybex-pulse-principals"),
        format!("{}\n", state.plan.reserved_device_id).as_bytes(),
        0o644,
    )?;
    atomic_write(
        &target_state.join("appliance-release.json"),
        &serde_json::to_vec_pretty(&json!({
            "schema": "cybex.pulse.installed-appliance.v1",
            "release": state.plan.release_version,
            "base_os": "ubuntu",
            "base_os_version": "26.04",
            "root_generation": "0",
            "at_rest_protection": "none"
        }))?,
        0o644,
    )?;
    atomic_write(
        &target_state.join("management-cidrs.txt"),
        format!("{}\n", state.plan.management_cidrs.join("\n")).as_bytes(),
        0o600,
    )?;
    stage_cache_backed_nix_store(target)?;
    append_unique_line(
        &target.join("etc/fstab"),
        "/var/cache/cybex-pulse/nix /nix none bind,nodev,nosuid,exec 0 0",
    )?;
    // The live and target paths are two mounts of the same CYBEX_STATE
    // filesystem. Flush the live file; it is already visible in the target.
    File::open(state_mount)?.sync_all()?;
    Ok(())
}

fn stage_cache_backed_nix_store(target: &Path) -> Result<()> {
    let target_nix = target.join("nix");
    let cache_nix = target.join("var/cache/cybex-pulse/nix");
    fs::create_dir_all(&target_nix).context("create installed Nix directory")?;
    fs::create_dir_all(&cache_nix).context("create cache-backed Nix store")?;

    let source_metadata = fs::metadata(&target_nix).context("inspect installed Nix directory")?;
    let cache_metadata = fs::metadata(&cache_nix).context("inspect cache-backed Nix directory")?;
    if source_metadata.dev() == cache_metadata.dev()
        && source_metadata.ino() == cache_metadata.ino()
    {
        return Ok(());
    }

    // Debian's Nix packages may seed /nix during installation. Preserve that
    // content before the persistent CYBEX_CACHE bind mount hides the root-side
    // directory on first boot.
    let status = StdCommand::new("cp")
        .args(["--archive", "--reflink=auto", "--"])
        .arg(target_nix.join("."))
        .arg(&cache_nix)
        .status()
        .context("copy installed Nix content into CYBEX_CACHE")?;
    if !status.success() {
        bail!("installed Nix content could not be staged in CYBEX_CACHE")
    }
    Ok(())
}

fn netplan(network: &PulseProvisioningNetworkPlan, plan: &SignedInstallPlan) -> Value {
    let mut device = serde_json::Map::new();
    device.insert(
        "match".to_string(),
        json!({"macaddress": plan.network_interface.mac}),
    );
    device.insert("set-name".to_string(), json!(plan.network_interface.name));
    device.insert("dhcp6".to_string(), json!(false));
    if network.mode == "dhcp" {
        device.insert("dhcp4".to_string(), json!(true));
    } else {
        device.insert("dhcp4".to_string(), json!(false));
        device.insert(
            "addresses".to_string(),
            json!([network.address_cidr.clone().unwrap_or_default()]),
        );
        device.insert(
            "routes".to_string(),
            json!([{"to":"default","via":network.gateway}]),
        );
        device.insert(
            "nameservers".to_string(),
            json!({"addresses": network.dns_servers}),
        );
    }
    json!({
        "network": {
            "version": 2,
            "renderer": "networkd",
            "ethernets": {"cybex-pulse": Value::Object(device)}
        }
    })
}

fn pulse_config(
    target: &Path,
    state: &DurableProvisioningState,
    public_base_url: &str,
) -> Result<String> {
    let admin_token = super::protocol::sha256_hex(format!(
        "CYBEX-PULSE-LOCAL-ADMIN-V1\0{}",
        state.device_private_key_b64
    ));
    let release_public_key =
        fs::read_to_string(target.join("usr/share/cybex-pulse/release-public-key"))
            .context("read installed Pulse release public key")?;
    let release_public_key = release_public_key.trim();
    if release_public_key.is_empty() {
        bail!("installed Pulse release public key is empty")
    }
    Ok(format!(
        "[server]\nlisten_addr = \"127.0.0.1:8080\"\npublic_base_url = {}\n\n\
         [paths]\ndata_dir = \"/var/lib/cybex-pulse\"\ndatabase_path = \"/var/lib/cybex-pulse/state/cybex-pulse.sqlite\"\nboot_assets_dir = \"/var/cache/cybex-pulse/www\"\nstatic_dir = \"/var/cache/cybex-pulse/www/assets\"\ntftp_dir = \"/var/cache/cybex-pulse/tftp\"\n\n\
         [auth]\nadmin_token = {}\n\n\
         [build]\nwork_dir = \"/var/cache/cybex-pulse/build\"\noutput_dir = \"/var/cache/cybex-pulse/build-outputs\"\nnix_binary = \"/usr/bin/nix\"\n\n\
         [cache]\nroot_dir = \"/var/cache/cybex-pulse/www/cache\"\nprivate_key_path = \"/var/lib/cybex-pulse/state/cache-private.pem\"\npublic_key_path = \"/var/lib/cybex-pulse/state/cache-public.pem\"\n\n\
         [update]\ntrusted_public_key = {}\n\n\
         [manage]\nenabled = true\napi_url = {}\norganization_id = {}\nstate_path = \"/var/lib/cybex-pulse/state/manage-state.json\"\nsync_interval_seconds = 30\nhttp_timeout_seconds = 30\n",
        toml_string(public_base_url),
        toml_string(&admin_token),
        toml_string(release_public_key),
        toml_string(&state.manage_origin),
        toml_string(&state.plan.organization_id.to_string()),
    ))
}

fn public_base_url(plan: &SignedInstallPlan) -> String {
    let address = plan
        .network
        .address_cidr
        .as_deref()
        .and_then(|value| value.split('/').next())
        .or_else(|| {
            plan.network_interface
                .addresses
                .iter()
                .find(|value| value.contains('.') && !value.starts_with("169.254."))
                .and_then(|value| value.split('/').next())
        });
    address
        .map(|address| format!("http://{address}"))
        .unwrap_or_else(|| {
            format!(
                "http://pulse-{}.local",
                device_id_suffix(&plan.reserved_device_id)
            )
        })
}

fn device_id_suffix(device_id: &str) -> String {
    device_id
        .strip_prefix("dev_")
        .unwrap_or(device_id)
        .chars()
        .take(12)
        .collect()
}

fn toml_string(value: &str) -> String {
    serde_json::to_string(value).expect("JSON string encoding is valid TOML basic-string encoding")
}

fn append_unique_line(path: &Path, line: &str) -> Result<()> {
    let existing = fs::read_to_string(path).unwrap_or_default();
    if existing.lines().any(|existing| existing == line) {
        return Ok(());
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o644)
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    if !existing.is_empty() && !existing.ends_with('\n') {
        file.write_all(b"\n")?;
    }
    writeln!(file, "{line}")?;
    file.sync_all()?;
    Ok(())
}

fn calculate_layout(sector_size: u64, total_sectors: u64) -> Result<([u64; 5], [u64; 5])> {
    let alignment = (1024 * 1024) / sector_size;
    let length = |bytes: u64| bytes / sector_size;
    let align_up = |value: u64| value.div_ceil(alignment) * alignment;
    let starts = {
        let one = alignment;
        let two = align_up(one + length(EFI_BYTES));
        let three = align_up(two + length(ROOT_BYTES));
        let four = align_up(three + length(STATE_BYTES));
        let five = align_up(four + length(SWAP_BYTES));
        [one, two, three, four, five]
    };
    let ends = [
        starts[0] + length(EFI_BYTES) - 1,
        starts[1] + length(ROOT_BYTES) - 1,
        starts[2] + length(STATE_BYTES) - 1,
        starts[3] + length(SWAP_BYTES) - 1,
        total_sectors
            .checked_sub(alignment + 1)
            .ok_or_else(|| anyhow!("target disk is too small"))?,
    ];
    if starts[4] >= ends[4] || ends[4] - starts[4] < length(40 * GIB) {
        bail!("target disk has insufficient cache capacity")
    }
    Ok((starts, ends))
}

fn partition_path(disk: &Path, number: u8) -> Result<PathBuf> {
    let value = disk
        .to_str()
        .ok_or_else(|| anyhow!("disk path is not UTF-8"))?;
    Ok(PathBuf::from(
        if value.as_bytes().last().is_some_and(u8::is_ascii_digit) {
            format!("{value}p{number}")
        } else {
            format!("{value}{number}")
        },
    ))
}

async fn settle_partitions(disk: &str) -> Result<()> {
    run_checked("partprobe", &[disk]).await?;
    run_checked("udevadm", &["settle", "--timeout=30"]).await
}

async fn command_u64(program: &str, arguments: &[&str]) -> Result<u64> {
    let output = Command::new(program)
        .args(arguments)
        .output()
        .await
        .with_context(|| format!("run {program}"))?;
    if !output.status.success() || output.stdout.len() > 128 {
        bail!("{program} failed")
    }
    String::from_utf8(output.stdout)
        .context("command output is not UTF-8")?
        .trim()
        .parse()
        .with_context(|| format!("parse {program} output"))
}

async fn run_checked(program: &str, arguments: &[&str]) -> Result<()> {
    let status = Command::new(program)
        .args(arguments)
        .status()
        .await
        .with_context(|| format!("run {program}"))?;
    if !status.success() {
        bail!("{program} failed")
    }
    Ok(())
}

fn atomic_write(path: &Path, body: &[u8], mode: u32) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("output path has no parent"))?;
    fs::create_dir_all(parent)
        .with_context(|| format!("create parent directory for {}", path.display()))?;
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("state"),
        Uuid::new_v4().simple()
    ));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&temporary)
            .with_context(|| format!("create {}", temporary.display()))?;
        file.write_all(body)?;
        file.sync_all()?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(mode))?;
        fs::rename(&temporary, path).with_context(|| format!("replace {}", path.display()))?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn durable_state_fixture() -> DurableProvisioningState {
        let now = Utc::now();
        let plan = serde_json::from_value(json!({
            "schema": "cybex.pulse.install-plan.v1",
            "id": "11111111-1111-4111-8111-111111111111",
            "organization_id": "22222222-2222-4222-8222-222222222222",
            "plan_revision": 1,
            "session_id": "33333333-3333-4333-8333-333333333333",
            "session_revision": 2,
            "inventory_sha256": "a".repeat(64),
            "hardware_digest": "b".repeat(64),
            "provisioning_public_key_fingerprint": "c".repeat(64),
            "reserved_device_id": "dev_0123456789abcdef0123456789abcdef",
            "display_name": "Recovery Pulse",
            "target_disk_id": "disk-1",
            "target_disk": {
                "id": "disk-1",
                "path": "/dev/sda",
                "model": "Disk",
                "serial": "serial-1",
                "wwn": "",
                "size_bytes": 171798691840_u64,
                "removable": false,
                "mounted": false,
                "held": false,
                "eligible": true,
                "blocker_codes": []
            },
            "network_interface": {
                "id": "pci-0000:00:03.0",
                "name": "enp0s3",
                "mac": "52:54:00:12:34:56",
                "link_up": true,
                "addresses": [],
                "gateway": null
            },
            "network": {
                "mode": "dhcp",
                "interface_id": "pci-0000:00:03.0",
                "address_cidr": null,
                "gateway": null,
                "dns_servers": []
            },
            "maintenance_window": {
                "timezone": "UTC",
                "weekday": 0,
                "start": "02:00",
                "duration_minutes": 120
            },
            "management_cidrs": [],
            "ssh_ca_public_keys": ["ssh-ed25519 AAAA recovery"],
            "base_os": "ubuntu",
            "base_os_version": "26.04",
            "release_version": "1.2.3",
            "at_rest_protection": "none",
            "issued_at": now,
            "expires_at": now + chrono::Duration::minutes(20),
            "plan_sha256": "d".repeat(64),
            "signature": "signature"
        }))
        .unwrap();
        DurableProvisioningState {
            schema: "cybex.pulse.provisioning-state.v1".to_string(),
            session_id: uuid::Uuid::parse_str("33333333-3333-4333-8333-333333333333").unwrap(),
            plan,
            manage_origin: "https://manage.cybex.net".to_string(),
            management_signing_public_key_b64: "management-key".to_string(),
            device_private_key_b64: "private-key".to_string(),
            device_public_key_b64: "public-key".to_string(),
            device_public_key_fingerprint: "fingerprint".to_string(),
            next_event_sequence: 3,
            identity_active: false,
            installation_complete: false,
            updated_at: now,
        }
    }

    #[test]
    fn recovery_probe_is_read_only_without_journal_replay() {
        let probe = recovery_probe_mount_options()
            .split(',')
            .collect::<Vec<_>>();
        assert_eq!(probe, ["ro", "noload", "nodev", "nosuid"]);
        let active = recovery_active_mount_options()
            .split(',')
            .collect::<Vec<_>>();
        assert_eq!(active, ["rw", "nodev", "nosuid"]);
        assert!(!active.contains(&"ro"));
        assert!(!active.contains(&"noload"));
    }

    #[test]
    fn preexisting_rw_state_mount_is_rejected_before_staging() {
        require_read_only_recovery_probe(true).unwrap();
        assert!(require_read_only_recovery_probe(false).is_err());
    }

    #[test]
    fn existing_probe_requires_read_only_ext4_with_replay_disabled() {
        let safe = b"36 29 8:3 / /run/cybex-state ro,nosuid,nodev - ext4 /dev/sda3 ro,norecovery\n";
        assert!(mountinfo_has_safe_recovery_probe(safe, b"/run/cybex-state"));
        let writable = b"36 29 8:3 / /run/cybex-state rw,nosuid,nodev - ext4 /dev/sda3 rw\n";
        assert!(!mountinfo_has_safe_recovery_probe(
            writable,
            b"/run/cybex-state"
        ));
        let replaying = b"36 29 8:3 / /run/cybex-state ro,nosuid,nodev - ext4 /dev/sda3 ro\n";
        assert!(!mountinfo_has_safe_recovery_probe(
            replaying,
            b"/run/cybex-state"
        ));
        let wrong_filesystem =
            b"36 29 8:3 / /run/cybex-state ro,nosuid,nodev,noload - xfs /dev/sda3 ro\n";
        assert!(!mountinfo_has_safe_recovery_probe(
            wrong_filesystem,
            b"/run/cybex-state"
        ));
        let escaped =
            b"36 29 8:3 / /run/cybex\\040state ro,nosuid,nodev,noload - ext4 /dev/sda3 ro\n";
        assert!(mountinfo_has_safe_recovery_probe(
            escaped,
            b"/run/cybex state"
        ));
    }

    #[test]
    fn journal_replay_may_only_advance_non_secret_recovery_progress() {
        let probed = durable_state_fixture();
        let mut active = probed.clone();
        active.next_event_sequence = 5;
        active.identity_active = true;
        active.updated_at += chrono::Duration::seconds(1);
        validate_recovered_state_transition(&probed, &active).unwrap();

        let mut changed_plan = active.clone();
        changed_plan.plan.release_version = "9.9.9".to_string();
        assert!(validate_recovered_state_transition(&probed, &changed_plan).is_err());

        let mut changed_key = active.clone();
        changed_key.device_private_key_b64 = "other-private-key".to_string();
        assert!(validate_recovered_state_transition(&probed, &changed_key).is_err());

        let mut regressed = probed.clone();
        regressed.next_event_sequence = 2;
        assert!(validate_recovered_state_transition(&probed, &regressed).is_err());
    }

    #[test]
    fn exact_layout_preserves_state_and_cache_minimum() {
        let sectors = (128 * GIB) / 512;
        let (starts, ends) = calculate_layout(512, sectors).unwrap();
        assert_eq!((ends[0] - starts[0] + 1) * 512, EFI_BYTES);
        assert_eq!((ends[1] - starts[1] + 1) * 512, ROOT_BYTES);
        assert_eq!((ends[2] - starts[2] + 1) * 512, STATE_BYTES);
        assert_eq!((ends[3] - starts[3] + 1) * 512, SWAP_BYTES);
        assert!((ends[4] - starts[4] + 1) * 512 >= 40 * GIB);
    }

    #[test]
    fn partition_paths_cover_nvme_and_sata() {
        assert_eq!(
            partition_path(Path::new("/dev/sda"), 3).unwrap(),
            Path::new("/dev/sda3")
        );
        assert_eq!(
            partition_path(Path::new("/dev/nvme0n1"), 3).unwrap(),
            Path::new("/dev/nvme0n1p3")
        );
    }

    #[test]
    fn missing_sgdisk_partition_is_not_treated_as_malformed() {
        assert!(
            parse_partition_info("Partition #1 does not exist.\n", 1)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn existing_sgdisk_partition_fields_are_parsed_exactly() {
        let body = "Partition GUID code: 0FC63DAF-8483-4772-8E79-3D69D8477DE4 (Linux filesystem)\n\
                    Partition unique GUID: 00000000-0000-0000-0000-000000000000\n\
                    First sector: 1024 (at 512.0 KiB)\n\
                    Last sector: 2047 (at 1023.5 KiB)\n\
                    Partition size: 1024 sectors (512.0 KiB)\n\
                    Attribute flags: 0000000000000000\n\
                    Partition name: 'CYBEX_STATE'\n";
        let partition = parse_partition_info(body, 3).unwrap().unwrap();
        assert_eq!(partition.first_sector, 1024);
        assert_eq!(partition.last_sector, 2047);
        assert_eq!(partition.type_code, "0FC63DAF-8483-4772-8E79-3D69D8477DE4");
        assert_eq!(partition.name, "CYBEX_STATE");
        partition
            .validate(1024, 2047, "8300", "CYBEX_STATE")
            .unwrap();
        assert!(
            partition
                .validate(1024, 2047, "8200", "CYBEX_STATE")
                .is_err()
        );
    }

    #[test]
    fn offline_apt_source_configures_curtins_installation_overlay() {
        let config = offline_apt_config(PackageDelivery::Embedded);
        assert_eq!(config["preserve_sources_list"], true);
        assert_eq!(config["fallback"], "offline-install");
        assert!(config.get("sources_list").is_none());
        assert!(
            config["conf"]
                .as_str()
                .unwrap()
                .contains("cybex-appliance.sources")
        );
        assert!(
            config["conf"]
                .as_str()
                .unwrap()
                .contains("sourceparts \"-\"")
        );
        assert_eq!(
            config["sources"]["cybex-appliance.sources"]["source"],
            "Types: deb\nURIs: file:///cdrom/cybex/apt\nSuites: ./\nComponents:\nTrusted: yes\n"
        );
    }

    #[test]
    fn live_offline_apt_source_replaces_ubuntu_and_cdrom_sources() {
        let root =
            std::env::temp_dir().join(format!("cybex-pulse-offline-apt-test-{}", Uuid::new_v4()));
        let sources_dir = root.join("etc/apt/sources.list.d");
        fs::create_dir_all(&sources_dir).unwrap();
        fs::write(sources_dir.join("cdrom.sources"), b"cdrom\n").unwrap();
        fs::write(sources_dir.join("ubuntu.sources"), b"ubuntu\n").unwrap();

        configure_live_offline_apt(&root, PackageDelivery::NetworkSnapshot).unwrap();

        assert!(!sources_dir.join("cdrom.sources").exists());
        assert!(!sources_dir.join("ubuntu.sources").exists());
        assert_eq!(
            fs::read_to_string(sources_dir.join("cybex-appliance.sources")).unwrap(),
            "Types: deb\nURIs: file:///run/cybex-appliance-repo/packages\nSuites: ./\nComponents:\nTrusted: yes\n"
        );
        assert_eq!(
            fs::read_to_string(root.join("etc/apt/sources.list")).unwrap(),
            "# Cybex Pulse installation uses the verified offline package snapshot.\n"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn offline_packages_install_only_after_media_is_visible_inside_target() {
        let commands = offline_package_install_commands(PackageDelivery::Embedded);
        let commands = commands.as_array().unwrap();
        let install_command = commands[0].as_array().unwrap();
        assert_eq!(install_command[0], "sh");
        assert_eq!(install_command[1], "-ceu");
        let install = install_command[2].as_str().unwrap();
        let mkdir = install.find("mkdir -p /target/cdrom").unwrap();
        let mount = install.find("mount --bind /cdrom /target/cdrom").unwrap();
        let source = install.find("/target/tmp/cybex-offline.list").unwrap();
        let update = install.find(" update;").unwrap();
        let packages = install.find(" install --yes").unwrap();
        assert!(mkdir < mount && mount < source && source < update && update < packages);
        assert!(install.contains("deb [trusted=yes] file:///cdrom/cybex/apt ./"));
        assert!(install.contains("chmod 0644 /target/tmp/cybex-offline.list"));
        assert_eq!(install.matches("Dir::Etc::sourcelist").count(), 2);
        assert_eq!(install.matches("Dir::Etc::sourceparts=-").count(), 2);
        assert!(install.contains("rm -f /target/tmp/cybex-offline.list"));
        assert!(install.contains("umount /target/cdrom"));
        assert!(install.contains("DEBIAN_FRONTEND=noninteractive"));
        assert!(
            StdCommand::new("sh")
                .args(["-n", "-c", install])
                .status()
                .unwrap()
                .success()
        );
        for package in [
            "cybex-pulse",
            "cybex-pulse-bootstrap",
            "cybex-pulse-appliance",
            "linux-generic",
            "shim-signed",
            "openssh-server",
            "btrfs-progs",
        ] {
            assert!(install.split_ascii_whitespace().any(|item| item == package));
        }
        assert!(
            commands[1]
                .as_str()
                .unwrap()
                .contains("installing_packages")
        );
    }

    #[test]
    fn network_snapshot_uses_curtins_run_bind_without_a_nested_mount() {
        let config = offline_apt_config(PackageDelivery::NetworkSnapshot);
        assert_eq!(config["preserve_sources_list"], true);
        assert!(config.get("sources_list").is_none());
        assert!(
            config["conf"]
                .as_str()
                .unwrap()
                .contains("cybex-appliance.sources")
        );
        assert_eq!(
            config["sources"]["cybex-appliance.sources"]["source"],
            "Types: deb\nURIs: file:///run/cybex-appliance-repo/packages\nSuites: ./\nComponents:\nTrusted: yes\n"
        );
        let commands = offline_package_install_commands(PackageDelivery::NetworkSnapshot);
        let install = commands[0].as_array().unwrap()[2].as_str().unwrap();
        let source = install
            .find("file:///run/cybex-appliance-repo/packages")
            .unwrap();
        let update = install.find(" update;").unwrap();
        assert!(source < update);
        assert!(!install.contains("mount --bind"));
        assert!(!install.contains("umount"));
        assert!(install.contains("trap 'rm -f /target/tmp/cybex-offline.list' EXIT"));
        assert!(
            StdCommand::new("sh")
                .args(["-n", "-c", install])
                .status()
                .unwrap()
                .success()
        );
    }

    #[test]
    fn preserved_efi_partition_is_the_explicit_uefi_bootloader_target() {
        let (starts, ends) = calculate_layout(512, (160 * GIB) / 512).unwrap();
        let prepared = PreparedStorage {
            disk_path: PathBuf::from("/dev/sda"),
            state_mount: PathBuf::from("/run/cybex-state"),
            sector_size: 512,
            partition_starts: starts,
            partition_ends: ends,
        };
        let config = storage_config(&prepared).unwrap();
        let actions = config.as_array().unwrap();
        let efi_partition = actions
            .iter()
            .find(|action| action["id"] == "efi-partition")
            .unwrap();
        assert_eq!(efi_partition["preserve"], true);
        assert_eq!(efi_partition["flag"], "boot");
        assert_eq!(efi_partition["grub_device"], true);

        let efi_mount = actions
            .iter()
            .find(|action| action["id"] == "efi-mount")
            .unwrap();
        assert_eq!(efi_mount["device"], "efi-format");
        assert_eq!(efi_mount["path"], "/boot/efi");
    }

    #[test]
    fn preserved_partitions_declare_the_exact_approved_byte_sizes() {
        let (starts, ends) = calculate_layout(512, (160 * GIB) / 512).unwrap();
        let prepared = PreparedStorage {
            disk_path: PathBuf::from("/dev/sda"),
            state_mount: PathBuf::from("/run/cybex-state"),
            sector_size: 512,
            partition_starts: starts,
            partition_ends: ends,
        };
        let config = storage_config(&prepared).unwrap();
        let actions = config.as_array().unwrap();
        let expected = [
            ("efi-partition", EFI_BYTES),
            ("root-partition", ROOT_BYTES),
            ("state-partition", STATE_BYTES),
            ("swap-partition", SWAP_BYTES),
            ("cache-partition", 93_413_441_536),
        ];
        for (id, size) in expected {
            let partition = actions.iter().find(|action| action["id"] == id).unwrap();
            assert_eq!(partition["size"], size);
        }
    }

    #[test]
    fn cache_backed_nix_staging_preserves_installer_seeded_content() {
        let root =
            std::env::temp_dir().join(format!("cybex-pulse-nix-stage-{}", Uuid::new_v4().simple()));
        let result = (|| -> Result<()> {
            let source = root.join("nix/store");
            fs::create_dir_all(&source)?;
            fs::write(source.join("seeded-path"), b"seeded")?;

            stage_cache_backed_nix_store(&root)?;

            assert_eq!(
                fs::read(root.join("var/cache/cybex-pulse/nix/store/seeded-path"))?,
                b"seeded"
            );
            Ok(())
        })();
        let _ = fs::remove_dir_all(&root);
        result.unwrap();
    }
}
