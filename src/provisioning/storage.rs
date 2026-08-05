use super::{
    DurableProvisioningState,
    inventory::ForgeProvisioningInventory,
    protocol::{ForgeProvisioningNetworkPlan, SignedInstallPlan},
};
use anyhow::{Context, Result, anyhow, bail};
use chrono::Utc;
use serde_json::{Value, json};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
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

#[derive(Clone, Debug)]
pub(crate) struct PreparedStorage {
    pub disk_path: PathBuf,
    pub state_mount: PathBuf,
    partition_starts: [u64; 5],
    partition_ends: [u64; 5],
}

pub(crate) fn existing_state_for_session(
    state_mount: &Path,
    session_id: Uuid,
) -> Result<Option<DurableProvisioningState>> {
    if !DurableProvisioningState::path(state_mount).exists() {
        mount_existing_state(state_mount)?;
    }
    let state_path = DurableProvisioningState::path(state_mount);
    if !state_path.exists() {
        return Ok(None);
    }
    let state = load_durable_state(state_mount)?;
    if state.session_id == session_id {
        if state.installation_complete {
            boot_installed_appliance()?;
            bail!("completed appliance reboot command unexpectedly returned")
        }
        return Ok(Some(state));
    }
    bail!("an existing CYBEX_STATE identity belongs to different provisioning media")
}

fn mount_existing_state(state_mount: &Path) -> Result<()> {
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
        return Ok(());
    }
    if candidates.len() != 1 {
        bail!("multiple CYBEX_STATE partitions are present; detach unrelated appliance disks")
    }
    fs::create_dir_all(state_mount).context("create existing state mountpoint")?;
    let status = StdCommand::new("mount")
        .args(["-o", "nodev,nosuid"])
        .arg(&candidates[0])
        .arg(state_mount)
        .status()
        .context("mount existing CYBEX_STATE")?;
    if !status.success() {
        bail!("existing CYBEX_STATE could not be mounted")
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
        if !(lower.contains("ubuntu") || lower.contains("cybex forge"))
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
    inventory: &ForgeProvisioningInventory,
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
        partition_starts: starts,
        partition_ends: ends,
    })
}

pub(crate) async fn resume_prepared_storage(
    plan: &SignedInstallPlan,
    inventory: &ForgeProvisioningInventory,
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
    if state.schema != "cybex.forge.provisioning-state.v1" {
        bail!("durable provisioning state schema is unsupported")
    }
    Ok(state)
}

pub(crate) fn write_autoinstall(
    path: &Path,
    prepared: &PreparedStorage,
    plan: &SignedInstallPlan,
) -> Result<()> {
    let disk = prepared
        .disk_path
        .to_str()
        .ok_or_else(|| anyhow!("target disk path is not UTF-8"))?;
    let hostname = format!("forge-{}", device_id_suffix(&plan.reserved_device_id));
    let config = json!({
        "autoinstall": {
            "version": 1,
            "interactive-sections": [],
            "locale": "en_US.UTF-8",
            "keyboard": {"layout": "us"},
            "refresh-installer": {"update": false},
            "apt": offline_apt_config(),
            "storage": {"config": storage_config(disk)},
            "packages": [
                "cybex-forge",
                "cybex-forge-bootstrap",
                "cybex-forge-appliance",
                "linux-generic",
                "linux-firmware",
                "intel-microcode",
                "amd64-microcode",
                "nginx-core",
                "tftpd-hpa",
                "ipxe",
                "nix-bin",
                "nix-setup-systemd",
                "openssh-server",
                "btrfs-progs",
                "watchdog"
            ],
            "ssh": {"install-server": true, "allow-pw": false},
            "user-data": {
                "hostname": hostname,
                "disable_root": true,
                "users": []
            },
            "late-commands": [
                "/cdrom/cybex/bootstrap/cybex-forge-bootstrap event --state-mount /run/cybex-state --stage installing_packages --status succeeded --progress-percent 80 --message 'Offline Ubuntu and Cybex packages installed'",
                "/cdrom/cybex/bootstrap/cybex-forge-bootstrap finalize-target --target /target --state-mount /run/cybex-state",
                "/cdrom/cybex/bootstrap/cybex-forge-bootstrap event --state-mount /run/cybex-state --stage installing_bootloader --status succeeded --progress-percent 95 --message 'Signed Ubuntu bootloader installed'",
                "/cdrom/cybex/bootstrap/cybex-forge-bootstrap event --state-mount /run/cybex-state --stage rebooting --status succeeded --progress-percent 99 --message 'Rebooting into the managed appliance'"
            ],
            "shutdown": "reboot"
        }
    });
    let body = serde_json::to_vec_pretty(&config).context("serialize autoinstall plan")?;
    atomic_write(path, &body, 0o600)
}

fn offline_apt_config() -> Value {
    json!({
        "preserve_sources_list": false,
        "fallback": "offline-install",
        // Curtin's `sources` form immediately runs apt-get update while
        // Subiquity is still configuring its temporary source overlay. The
        // installation media is not bind-mounted there yet, so a file:///cdrom
        // source fails before installation starts. A complete sources-list
        // template is written without that eager probe and is consumed after
        // Subiquity makes /cdrom available to the installation environment.
        "sources_list": "deb [trusted=yes] file:///cdrom/cybex/apt ./"
    })
}

fn storage_config(disk: &str) -> Value {
    json!([
        {"type":"disk","id":"disk0","path":disk,"ptable":"gpt","preserve":true,"wipe":null},
        {"type":"partition","id":"efi-partition","device":"disk0","number":1,"preserve":true},
        {"type":"partition","id":"root-partition","device":"disk0","number":2,"preserve":true},
        {"type":"partition","id":"state-partition","device":"disk0","number":3,"preserve":true},
        {"type":"partition","id":"swap-partition","device":"disk0","number":4,"preserve":true},
        {"type":"partition","id":"cache-partition","device":"disk0","number":5,"preserve":true},
        {"type":"format","id":"efi-format","volume":"efi-partition","fstype":"fat32","label":"CYBEX_EFI"},
        {"type":"format","id":"root-format","volume":"root-partition","fstype":"btrfs","label":"CYBEX_ROOT"},
        {"type":"format","id":"state-format","volume":"state-partition","fstype":"ext4","label":"CYBEX_STATE","preserve":true},
        {"type":"format","id":"swap-format","volume":"swap-partition","fstype":"swap","label":"CYBEX_SWAP"},
        {"type":"format","id":"cache-format","volume":"cache-partition","fstype":"ext4","label":"CYBEX_CACHE"},
        {"type":"mount","id":"root-mount","device":"root-format","path":"/","options":"defaults"},
        {"type":"mount","id":"efi-mount","device":"efi-format","path":"/boot/efi","options":"umask=0077"},
        {"type":"mount","id":"state-mount","device":"state-format","path":"/var/lib/cybex-forge/state","options":"nodev,nosuid"},
        {"type":"mount","id":"cache-mount","device":"cache-format","path":"/var/cache/cybex-forge","options":"nodev,nosuid,exec"},
        {"type":"mount","id":"swap-mount","device":"swap-format","path":"none"}
    ])
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
    let target_state = target.join("var/lib/cybex-forge/state");
    let target_etc = target.join("etc/cybex-forge");
    let target_ssh = target.join("etc/ssh");
    let target_netplan = target.join("etc/netplan");
    for directory in [&target_state, &target_etc, &target_ssh, &target_netplan] {
        fs::create_dir_all(directory).with_context(|| format!("create {}", directory.display()))?;
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
    let config = forge_config(target, state, &public_base_url)?;
    atomic_write(&target_etc.join("config.toml"), config.as_bytes(), 0o600)?;
    atomic_write(
        &target_netplan.join("90-cybex-forge.yaml"),
        &serde_json::to_vec_pretty(&netplan(&state.plan.network, &state.plan))?,
        0o600,
    )?;
    atomic_write(
        &target_state.join("netplan-approved.json"),
        &serde_json::to_vec_pretty(&netplan(&state.plan.network, &state.plan))?,
        0o600,
    )?;
    let fallback = ForgeProvisioningNetworkPlan {
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
        &target_ssh.join("cybex-forge-ca.pub"),
        format!("{}\n", state.plan.ssh_ca_public_keys.join("\n")).as_bytes(),
        0o644,
    )?;
    atomic_write(
        &target_ssh.join("cybex-forge-principals"),
        format!("{}\n", state.plan.reserved_device_id).as_bytes(),
        0o644,
    )?;
    atomic_write(
        &target_state.join("appliance-release.json"),
        &serde_json::to_vec_pretty(&json!({
            "schema": "cybex.forge.installed-appliance.v1",
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
        "/var/cache/cybex-forge/nix /nix none bind,nodev,nosuid,exec 0 0",
    )?;
    // The live and target paths are two mounts of the same CYBEX_STATE
    // filesystem. Flush the live file; it is already visible in the target.
    File::open(state_mount)?.sync_all()?;
    Ok(())
}

fn stage_cache_backed_nix_store(target: &Path) -> Result<()> {
    let target_nix = target.join("nix");
    let cache_nix = target.join("var/cache/cybex-forge/nix");
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

fn netplan(network: &ForgeProvisioningNetworkPlan, plan: &SignedInstallPlan) -> Value {
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
            "ethernets": {"cybex-forge": Value::Object(device)}
        }
    })
}

fn forge_config(
    target: &Path,
    state: &DurableProvisioningState,
    public_base_url: &str,
) -> Result<String> {
    let admin_token = super::protocol::sha256_hex(format!(
        "CYBEX-FORGE-LOCAL-ADMIN-V1\0{}",
        state.device_private_key_b64
    ));
    let release_public_key =
        fs::read_to_string(target.join("usr/share/cybex-forge/release-public-key"))
            .context("read installed Forge release public key")?;
    let release_public_key = release_public_key.trim();
    if release_public_key.is_empty() {
        bail!("installed Forge release public key is empty")
    }
    Ok(format!(
        "[server]\nlisten_addr = \"127.0.0.1:8080\"\npublic_base_url = {}\n\n\
         [paths]\ndata_dir = \"/var/lib/cybex-forge\"\ndatabase_path = \"/var/lib/cybex-forge/state/cybex-forge.sqlite\"\nboot_assets_dir = \"/var/cache/cybex-forge/www\"\nstatic_dir = \"/var/cache/cybex-forge/www/assets\"\ntftp_dir = \"/var/cache/cybex-forge/tftp\"\n\n\
         [auth]\nadmin_token = {}\n\n\
         [build]\nwork_dir = \"/var/cache/cybex-forge/build\"\noutput_dir = \"/var/cache/cybex-forge/build-outputs\"\nnix_binary = \"/usr/bin/nix\"\n\n\
         [cache]\nroot_dir = \"/var/cache/cybex-forge/www/cache\"\nprivate_key_path = \"/var/lib/cybex-forge/state/cache-private.pem\"\npublic_key_path = \"/var/lib/cybex-forge/state/cache-public.pem\"\n\n\
         [update]\ntrusted_public_key = {}\n\n\
         [manage]\nenabled = true\napi_url = {}\norganization_id = {}\nstate_path = \"/var/lib/cybex-forge/state/manage-state.json\"\nsync_interval_seconds = 30\nhttp_timeout_seconds = 30\n",
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
                "http://forge-{}.local",
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
    fn offline_apt_source_does_not_trigger_curtins_early_repository_probe() {
        let config = offline_apt_config();
        assert_eq!(config["preserve_sources_list"], false);
        assert_eq!(config["fallback"], "offline-install");
        assert_eq!(
            config["sources_list"],
            "deb [trusted=yes] file:///cdrom/cybex/apt ./"
        );
        assert!(config.get("sources").is_none());
    }

    #[test]
    fn cache_backed_nix_staging_preserves_installer_seeded_content() {
        let root =
            std::env::temp_dir().join(format!("cybex-forge-nix-stage-{}", Uuid::new_v4().simple()));
        let result = (|| -> Result<()> {
            let source = root.join("nix/store");
            fs::create_dir_all(&source)?;
            fs::write(source.join("seeded-path"), b"seeded")?;

            stage_cache_backed_nix_store(&root)?;

            assert_eq!(
                fs::read(root.join("var/cache/cybex-forge/nix/store/seeded-path"))?,
                b"seeded"
            );
            Ok(())
        })();
        let _ = fs::remove_dir_all(&root);
        result.unwrap();
    }
}
