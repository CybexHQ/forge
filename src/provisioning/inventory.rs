use super::protocol::SignedInstallPlan;
use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    process::{Command as StdCommand, Output},
    time::Duration,
};
use tokio::process::Command;

const MIN_DISK_BYTES: u64 = 128 * 1024 * 1024 * 1024;
const STATIC_PREFLIGHT_ROUTE_TABLE: &str = "42666";
const STATIC_PREFLIGHT_RULE_PRIORITY: &str = "42666";
const STATIC_PREFLIGHT_OUTPUT_LIMIT: usize = 16 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PulseProvisioningEthernetInterface {
    pub id: String,
    pub name: String,
    pub mac: String,
    pub link_up: bool,
    pub addresses: Vec<String>,
    pub gateway: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PulseProvisioningDisk {
    pub id: String,
    pub path: String,
    pub model: String,
    pub serial: String,
    pub wwn: String,
    pub size_bytes: u64,
    pub removable: bool,
    pub mounted: bool,
    pub held: bool,
    pub eligible: bool,
    #[serde(default)]
    pub blocker_codes: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PulseProvisioningInventory {
    pub manufacturer: String,
    pub model: String,
    pub serial_number: String,
    pub asset_tag: String,
    pub cpu_model: String,
    pub cpu_cores: u32,
    pub memory_bytes: u64,
    pub firmware_version: String,
    pub kernel_version: String,
    pub boot_mode: String,
    pub secure_boot: bool,
    pub virtualization: String,
    #[serde(default)]
    pub ethernet_interfaces: Vec<PulseProvisioningEthernetInterface>,
    #[serde(default)]
    pub disks: Vec<PulseProvisioningDisk>,
}

pub(crate) async fn collect_inventory() -> Result<PulseProvisioningInventory> {
    let mut ethernet_interfaces = collect_ethernet_interfaces().await?;
    ethernet_interfaces.sort_by(|left, right| left.id.cmp(&right.id));
    let mut disks = collect_disks().await?;
    disks.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(PulseProvisioningInventory {
        manufacturer: clean(&read_trimmed("/sys/class/dmi/id/sys_vendor"), 256),
        model: clean(&read_trimmed("/sys/class/dmi/id/product_name"), 256),
        serial_number: clean(&read_trimmed("/sys/class/dmi/id/product_serial"), 256),
        asset_tag: clean(&read_trimmed("/sys/class/dmi/id/chassis_asset_tag"), 256),
        cpu_model: clean(&cpu_model(), 256),
        cpu_cores: std::thread::available_parallelism()
            .map(|value| value.get() as u32)
            .unwrap_or(0),
        memory_bytes: memory_bytes(),
        firmware_version: clean(&read_trimmed("/sys/class/dmi/id/bios_version"), 256),
        kernel_version: clean(&command_text("uname", &["-r"]).await, 256),
        boot_mode: if Path::new("/sys/firmware/efi").is_dir() {
            "uefi".to_string()
        } else {
            "legacy".to_string()
        },
        secure_boot: secure_boot_enabled(),
        virtualization: clean(&command_text("systemd-detect-virt", &["--vm"]).await, 256),
        ethernet_interfaces,
        disks,
    })
}

pub(crate) fn inventory_sha256(inventory: &PulseProvisioningInventory) -> Result<String> {
    let bytes = serde_json::to_vec(inventory).context("serialize hardware inventory")?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

pub(crate) fn hardware_digest(inventory: &PulseProvisioningInventory) -> Result<String> {
    let value = canonical_json(json!({
        "manufacturer": inventory.manufacturer,
        "model": inventory.model,
        "serial_number": inventory.serial_number,
        "asset_tag": inventory.asset_tag,
        "cpu_model": inventory.cpu_model,
        "cpu_cores": inventory.cpu_cores,
        "memory_bytes": inventory.memory_bytes,
        "ethernet": inventory.ethernet_interfaces.iter().map(|interface| json!({
            "id": interface.id,
            "mac": interface.mac,
        })).collect::<Vec<_>>(),
        "disks": inventory.disks.iter().map(|disk| json!({
            "id": disk.id,
            "serial": disk.serial,
            "wwn": disk.wwn,
            "size_bytes": disk.size_bytes,
        })).collect::<Vec<_>>(),
    }));
    let bytes = serde_json::to_vec(&value).context("serialize hardware identity")?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

pub(crate) fn revalidate_plan_hardware(
    plan: &SignedInstallPlan,
    inventory: &PulseProvisioningInventory,
) -> Result<()> {
    if hardware_digest(inventory)? != plan.hardware_digest {
        bail!("stable hardware identity changed after approval")
    }
    if inventory.boot_mode != "uefi" || !inventory.secure_boot {
        bail!("UEFI Secure Boot must remain enabled")
    }
    let disk = inventory
        .disks
        .iter()
        .find(|disk| disk.id == plan.target_disk_id)
        .ok_or_else(|| anyhow!("approved target disk is missing"))?;
    if disk != &plan.target_disk || !disk.eligible {
        bail!("approved disk identity or eligibility changed")
    }
    let interface = inventory
        .ethernet_interfaces
        .iter()
        .find(|interface| interface.id == plan.network_interface.id)
        .ok_or_else(|| anyhow!("approved wired interface is missing"))?;
    if interface.name != plan.network_interface.name
        || interface.mac != plan.network_interface.mac
        || !interface.link_up
    {
        bail!("approved wired interface identity or link state changed")
    }
    Ok(())
}

pub(crate) fn revalidate_durable_plan_hardware(
    plan: &SignedInstallPlan,
    inventory: &PulseProvisioningInventory,
) -> Result<()> {
    if hardware_digest(inventory)? != plan.hardware_digest
        || inventory.boot_mode != "uefi"
        || !inventory.secure_boot
    {
        bail!("hardware identity or Secure Boot changed during installation recovery")
    }
    let disk = inventory
        .disks
        .iter()
        .find(|disk| disk.id == plan.target_disk_id)
        .ok_or_else(|| anyhow!("approved target disk is missing during recovery"))?;
    if disk.id != plan.target_disk.id
        || disk.path != plan.target_disk.path
        || disk.model != plan.target_disk.model
        || disk.serial != plan.target_disk.serial
        || disk.wwn != plan.target_disk.wwn
        || disk.size_bytes != plan.target_disk.size_bytes
        || disk.removable
        || disk.held
    {
        bail!("approved disk identity changed during installation recovery")
    }
    Ok(())
}

pub(crate) async fn preflight_network(
    plan: &SignedInstallPlan,
    inventory: &PulseProvisioningInventory,
    manage_origin: &str,
) -> Result<()> {
    let interface = inventory
        .ethernet_interfaces
        .iter()
        .find(|interface| interface.id == plan.network.interface_id && interface.link_up)
        .ok_or_else(|| anyhow!("approved wired interface is missing or disconnected"))?;
    match plan.network.mode.as_str() {
        "dhcp" => {
            if plan.network.address_cidr.is_some()
                || plan.network.gateway.is_some()
                || !plan.network.dns_servers.is_empty()
            {
                bail!("DHCP plan contains unexpected static settings")
            }
        }
        "static" => {
            let cidr = plan
                .network
                .address_cidr
                .as_deref()
                .ok_or_else(|| anyhow!("static plan omitted address_cidr"))?;
            let (address, prefix) = parse_ipv4_cidr(cidr)?;
            let gateway: Ipv4Addr = plan
                .network
                .gateway
                .as_deref()
                .ok_or_else(|| anyhow!("static plan omitted gateway"))?
                .parse()
                .context("static gateway is invalid")?;
            if !same_ipv4_subnet(address, gateway, prefix) || address == gateway {
                bail!("static gateway is outside the selected subnet")
            }
            let dns_servers = plan
                .network
                .dns_servers
                .iter()
                .map(|server| {
                    server
                        .parse::<Ipv4Addr>()
                        .with_context(|| format!("static DNS server {server} is not IPv4"))
                })
                .collect::<Result<Vec<_>>>()?;
            if dns_servers.is_empty() {
                bail!("static DNS configuration is invalid")
            }
            let manage_host = manage_https_host(manage_origin)?;
            let duplicate_free = bounded_command_success(
                "arping",
                &[
                    "-D",
                    "-q",
                    "-c",
                    "2",
                    "-I",
                    &interface.name,
                    &address.to_string(),
                ],
                Duration::from_secs(8),
            )
            .await
            .context("run duplicate-address detection")?;
            if !duplicate_free {
                bail!("static address is already in use or duplicate detection failed")
            }

            ensure_static_probe_namespace_available().await?;
            let address_text = address.to_string();
            let address_cidr = format!("{address}/{prefix}");
            let source_rule = format!("{address}/32");
            let existing_address = interface.addresses.iter().find(|candidate| {
                candidate
                    .split_once('/')
                    .is_some_and(|(candidate, _)| candidate == address_text)
            });
            if existing_address.is_some_and(|candidate| candidate != &address_cidr) {
                bail!("the static address is already configured with a different prefix")
            }
            let mut probe = StaticNetworkProbe::new(
                interface.name.clone(),
                address_cidr.clone(),
                source_rule.clone(),
            );
            if existing_address.is_none() {
                run_ip(&[
                    "-4",
                    "address",
                    "add",
                    &address_cidr,
                    "dev",
                    &interface.name,
                ])
                .await
                .context("install candidate static address for connectivity preflight")?;
                probe.address_added = true;
            }

            let network = ipv4_network(address, prefix);
            let network_cidr = format!("{network}/{prefix}");
            run_ip(&[
                "-4",
                "route",
                "add",
                "table",
                STATIC_PREFLIGHT_ROUTE_TABLE,
                &network_cidr,
                "dev",
                &interface.name,
                "src",
                &address_text,
            ])
            .await
            .context("install candidate static subnet route")?;
            probe.route_owned = true;
            let gateway_text = gateway.to_string();
            run_ip(&[
                "-4",
                "route",
                "add",
                "table",
                STATIC_PREFLIGHT_ROUTE_TABLE,
                "default",
                "via",
                &gateway_text,
                "dev",
                &interface.name,
                "src",
                &address_text,
                "onlink",
            ])
            .await
            .context("install candidate static default route")?;
            run_ip(&[
                "-4",
                "rule",
                "add",
                "priority",
                STATIC_PREFLIGHT_RULE_PRIORITY,
                "from",
                &source_rule,
                "lookup",
                STATIC_PREFLIGHT_ROUTE_TABLE,
            ])
            .await
            .context("install candidate static source-policy rule")?;
            probe.rule_owned = true;

            let gateway_reachable = bounded_command_success(
                "arping",
                &[
                    "-q",
                    "-c",
                    "2",
                    "-I",
                    &interface.name,
                    "-s",
                    &address_text,
                    &gateway_text,
                ],
                Duration::from_secs(8),
            )
            .await
            .context("probe approved static gateway")?;
            if !gateway_reachable {
                bail!("approved static gateway did not answer on the selected interface")
            }

            let mut resolved_addresses = Vec::new();
            for dns_server in dns_servers {
                let dns_server = dns_server.to_string();
                let dns_selector = format!("@{dns_server}");
                let output = bounded_command_output(
                    "dig",
                    &[
                        "+short",
                        "+time=3",
                        "+tries=1",
                        "-b",
                        &address_text,
                        &dns_selector,
                        &manage_host,
                        "A",
                    ],
                    Duration::from_secs(8),
                )
                .await
                .with_context(|| {
                    format!("query Management through approved DNS server {dns_server}")
                })?;
                let answers = String::from_utf8(output)
                    .context("approved DNS server returned non-UTF-8 output")?
                    .lines()
                    .filter_map(|line| line.trim().parse::<Ipv4Addr>().ok())
                    .collect::<Vec<_>>();
                if answers.is_empty() {
                    bail!("approved DNS server {dns_server} did not resolve the Management origin")
                }
                resolved_addresses.extend(answers);
            }
            resolved_addresses.sort_unstable();
            resolved_addresses.dedup();

            let mut https_reachable = false;
            for resolved in resolved_addresses {
                let resolved = resolved.to_string();
                let resolve = format!("{manage_host}:443:{resolved}");
                let reachable = bounded_command_success(
                    "curl",
                    &[
                        "--silent",
                        "--show-error",
                        "--output",
                        "/dev/null",
                        "--connect-timeout",
                        "5",
                        "--max-time",
                        "15",
                        "--proto",
                        "=https",
                        "--tlsv1.2",
                        "--noproxy",
                        "*",
                        "--interface",
                        &address_text,
                        "--resolve",
                        &resolve,
                        manage_origin,
                    ],
                    Duration::from_secs(20),
                )
                .await
                .context("probe Management HTTPS through approved static network")?;
                if reachable {
                    https_reachable = true;
                    break;
                }
            }
            if !https_reachable {
                bail!("approved static network cannot establish Management HTTPS")
            }
        }
        _ => bail!("approved network mode is unsupported"),
    }
    Ok(())
}

struct StaticNetworkProbe {
    interface: String,
    address_cidr: String,
    source_rule: String,
    address_added: bool,
    route_owned: bool,
    rule_owned: bool,
}

impl StaticNetworkProbe {
    fn new(interface: String, address_cidr: String, source_rule: String) -> Self {
        Self {
            interface,
            address_cidr,
            source_rule,
            address_added: false,
            route_owned: false,
            rule_owned: false,
        }
    }
}

impl Drop for StaticNetworkProbe {
    fn drop(&mut self) {
        if self.rule_owned {
            let _ = StdCommand::new("ip")
                .args([
                    "-4",
                    "rule",
                    "del",
                    "priority",
                    STATIC_PREFLIGHT_RULE_PRIORITY,
                    "from",
                    &self.source_rule,
                    "lookup",
                    STATIC_PREFLIGHT_ROUTE_TABLE,
                ])
                .status();
        }
        if self.route_owned {
            let _ = StdCommand::new("ip")
                .args([
                    "-4",
                    "route",
                    "flush",
                    "table",
                    STATIC_PREFLIGHT_ROUTE_TABLE,
                ])
                .status();
        }
        if self.address_added {
            let _ = StdCommand::new("ip")
                .args([
                    "-4",
                    "address",
                    "del",
                    &self.address_cidr,
                    "dev",
                    &self.interface,
                ])
                .status();
        }
    }
}

async fn ensure_static_probe_namespace_available() -> Result<()> {
    let rules = bounded_command_output("ip", &["-4", "rule", "show"], Duration::from_secs(5))
        .await
        .context("inspect IPv4 policy rules")?;
    let table_in_use = String::from_utf8(rules)
        .context("IPv4 policy rule output is not UTF-8")?
        .lines()
        .any(|line| {
            line.split_whitespace()
                .any(|field| field.trim_end_matches(':') == STATIC_PREFLIGHT_RULE_PRIORITY)
                || line
                    .split_whitespace()
                    .any(|field| field == STATIC_PREFLIGHT_ROUTE_TABLE)
        });
    if table_in_use {
        bail!("reserved static-network preflight policy namespace is already in use")
    }
    let routes = bounded_command_output(
        "ip",
        &["-4", "route", "show", "table", STATIC_PREFLIGHT_ROUTE_TABLE],
        Duration::from_secs(5),
    )
    .await
    .context("inspect static-network preflight route table")?;
    if !String::from_utf8(routes)
        .context("IPv4 route output is not UTF-8")?
        .trim()
        .is_empty()
    {
        bail!("reserved static-network preflight route table is already in use")
    }
    Ok(())
}

async fn run_ip(arguments: &[&str]) -> Result<()> {
    bounded_command_output("ip", arguments, Duration::from_secs(5))
        .await
        .map(|_| ())
}

async fn bounded_command_output(
    program: &str,
    arguments: &[&str],
    timeout: Duration,
) -> Result<Vec<u8>> {
    let output = bounded_command(program, arguments, timeout).await?;
    if !output.status.success() {
        bail!("{program} exited unsuccessfully")
    }
    Ok(output.stdout)
}

async fn bounded_command_success(
    program: &str,
    arguments: &[&str],
    timeout: Duration,
) -> Result<bool> {
    Ok(bounded_command(program, arguments, timeout)
        .await?
        .status
        .success())
}

async fn bounded_command(program: &str, arguments: &[&str], timeout: Duration) -> Result<Output> {
    let mut command = Command::new(program);
    command.args(arguments).kill_on_drop(true);
    let output = tokio::time::timeout(timeout, command.output())
        .await
        .with_context(|| format!("{program} timed out"))?
        .with_context(|| format!("run {program}"))?;
    if output.stdout.len() > STATIC_PREFLIGHT_OUTPUT_LIMIT
        || output.stderr.len() > STATIC_PREFLIGHT_OUTPUT_LIMIT
    {
        bail!("{program} returned excessive output")
    }
    Ok(output)
}

fn manage_https_host(manage_origin: &str) -> Result<String> {
    let url = reqwest::Url::parse(manage_origin).context("Management origin is not a valid URL")?;
    if url.scheme() != "https"
        || url.port_or_known_default() != Some(443)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        bail!("Management origin must be an HTTPS origin on port 443")
    }
    url.host_str()
        .filter(|host| !host.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("Management origin omitted its host"))
}

fn ipv4_network(address: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let mask = u32::MAX.checked_shl((32 - prefix).into()).unwrap_or(0);
    Ipv4Addr::from(u32::from(address) & mask)
}

async fn collect_ethernet_interfaces() -> Result<Vec<PulseProvisioningEthernetInterface>> {
    let mut interfaces = Vec::new();
    for entry in fs::read_dir("/sys/class/net").context("enumerate network interfaces")? {
        let entry = entry.context("read network interface")?;
        let name = entry.file_name().to_string_lossy().to_string();
        let root = entry.path();
        if name == "lo"
            || root.join("wireless").exists()
            || read_trimmed(root.join("type")) != "1"
            || !root.join("device").exists()
        {
            continue;
        }
        let mac = normalize_mac(&read_trimmed(root.join("address")))?;
        let properties = command_text(
            "udevadm",
            &[
                "info",
                "--query=property",
                &format!("--path={}", root.display()),
            ],
        )
        .await;
        let stable_path = properties
            .lines()
            .find_map(|line| line.strip_prefix("ID_PATH="))
            .unwrap_or("");
        let fallback_id = format!("mac-{mac}");
        let id = clean(
            if stable_path.is_empty() {
                &fallback_id
            } else {
                stable_path
            },
            256,
        );
        let network = command_json("ip", &["-j", "address", "show", "dev", &name]).await;
        let mut addresses = network
            .as_array()
            .and_then(|rows| rows.first())
            .and_then(|row| row.get("addr_info"))
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|address| {
                let local = address.get("local")?.as_str()?;
                let prefix = address.get("prefixlen")?.as_u64()?;
                Some(format!("{local}/{prefix}"))
            })
            .collect::<Vec<_>>();
        addresses.sort();
        addresses.dedup();
        let routes = command_json("ip", &["-j", "route", "show", "default", "dev", &name]).await;
        let gateway = routes
            .as_array()
            .and_then(|rows| rows.first())
            .and_then(|route| route.get("gateway"))
            .and_then(Value::as_str)
            .map(|value| clean(value, 128));
        interfaces.push(PulseProvisioningEthernetInterface {
            id,
            name: clean(&name, 64),
            mac,
            link_up: read_trimmed(root.join("carrier")) == "1",
            addresses,
            gateway,
        });
    }
    Ok(interfaces)
}

async fn collect_disks() -> Result<Vec<PulseProvisioningDisk>> {
    let output = Command::new("lsblk")
        .args([
            "--json",
            "--bytes",
            "--output",
            "NAME,KNAME,PATH,TYPE,SIZE,MODEL,SERIAL,WWN,RM,MOUNTPOINTS,RO,HOTPLUG",
        ])
        .output()
        .await
        .context("run lsblk")?;
    if !output.status.success() || output.stdout.len() > 4 * 1024 * 1024 {
        bail!("lsblk could not provide bounded disk inventory")
    }
    let value: Value = serde_json::from_slice(&output.stdout).context("parse lsblk inventory")?;
    let rows = value
        .get("blockdevices")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("lsblk inventory omitted blockdevices"))?;
    let mut disks = Vec::new();
    for row in rows {
        if row.get("type").and_then(Value::as_str) != Some("disk") {
            continue;
        }
        let path = row
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("disk inventory omitted path"))?;
        let size_bytes = value_u64(row.get("size")).unwrap_or(0);
        let removable = value_bool(row.get("rm")) || value_bool(row.get("hotplug"));
        let mounted = has_mountpoint(row);
        let kname = row.get("kname").and_then(Value::as_str).unwrap_or("");
        let held = value_bool(row.get("ro"))
            || fs::read_dir(format!("/sys/class/block/{kname}/holders"))
                .ok()
                .is_some_and(|mut entries| entries.next().is_some());
        let mut blocker_codes = Vec::new();
        if removable {
            blocker_codes.push("removable_disk".to_string());
        }
        if mounted {
            blocker_codes.push("mounted_disk".to_string());
        }
        if held {
            blocker_codes.push("held_disk".to_string());
        }
        if size_bytes < MIN_DISK_BYTES {
            blocker_codes.push("disk_too_small".to_string());
        }
        let id = stable_disk_id(Path::new(path))?;
        disks.push(PulseProvisioningDisk {
            id,
            path: clean(path, 256),
            model: clean(value_string(row.get("model")), 128),
            serial: clean(value_string(row.get("serial")), 128),
            wwn: clean(value_string(row.get("wwn")), 128),
            size_bytes,
            removable,
            mounted,
            held,
            eligible: blocker_codes.is_empty(),
            blocker_codes,
        });
    }
    Ok(disks)
}

fn stable_disk_id(path: &Path) -> Result<String> {
    let target =
        fs::canonicalize(path).with_context(|| format!("resolve disk path {}", path.display()))?;
    let mut candidates = Vec::new();
    if let Ok(entries) = fs::read_dir("/dev/disk/by-id") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.contains("-part") {
                continue;
            }
            if fs::canonicalize(entry.path()).ok().as_ref() == Some(&target) {
                candidates.push(name);
            }
        }
    }
    candidates.sort_by_key(|name| (disk_id_priority(name), name.clone()));
    candidates
        .into_iter()
        .next()
        .map(|name| clean(&name, 512))
        .ok_or_else(|| {
            anyhow!(
                "disk {} has no stable /dev/disk/by-id identity",
                path.display()
            )
        })
}

fn disk_id_priority(name: &str) -> u8 {
    if name.starts_with("nvme-eui.") || name.starts_with("wwn-") {
        0
    } else if name.starts_with("ata-") || name.starts_with("scsi-") {
        1
    } else if name.starts_with("virtio-") {
        2
    } else {
        3
    }
}

fn has_mountpoint(value: &Value) -> bool {
    let mounted_here = value
        .get("mountpoints")
        .and_then(Value::as_array)
        .is_some_and(|mounts| mounts.iter().any(|mount| !mount.is_null()));
    mounted_here
        || value
            .get("children")
            .and_then(Value::as_array)
            .is_some_and(|children| children.iter().any(has_mountpoint))
}

fn value_bool(value: Option<&Value>) -> bool {
    value.is_some_and(|value| {
        value.as_bool().unwrap_or(false)
            || value.as_u64().unwrap_or(0) != 0
            || value.as_str().is_some_and(|value| value == "1")
    })
}

fn value_u64(value: Option<&Value>) -> Option<u64> {
    value.and_then(|value| {
        value
            .as_u64()
            .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
    })
}

fn value_string(value: Option<&Value>) -> &str {
    value.and_then(Value::as_str).unwrap_or("")
}

fn secure_boot_enabled() -> bool {
    let Ok(entries) = fs::read_dir("/sys/firmware/efi/efivars") else {
        return false;
    };
    entries.flatten().any(|entry| {
        let name = entry.file_name();
        if !name.to_string_lossy().starts_with("SecureBoot-") {
            return false;
        }
        fs::read(entry.path())
            .ok()
            .is_some_and(|value| value.get(4) == Some(&1))
    })
}

fn cpu_model() -> String {
    fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|body| {
            body.lines().find_map(|line| {
                let (name, value) = line.split_once(':')?;
                (name.trim() == "model name").then(|| value.trim().to_string())
            })
        })
        .unwrap_or_default()
}

fn memory_bytes() -> u64 {
    fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|body| {
            body.lines().find_map(|line| {
                let value = line.strip_prefix("MemTotal:")?.trim();
                value
                    .strip_suffix(" kB")?
                    .trim()
                    .parse::<u64>()
                    .ok()
                    .and_then(|kilobytes| kilobytes.checked_mul(1024))
            })
        })
        .unwrap_or(0)
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
    let body = command_text(program, arguments).await;
    serde_json::from_str(&body).unwrap_or(Value::Null)
}

fn read_trimmed(path: impl Into<PathBuf>) -> String {
    fs::read_to_string(path.into())
        .map(|value| value.trim().to_string())
        .unwrap_or_default()
}

fn clean(value: &str, max: usize) -> String {
    value.trim().chars().take(max).collect()
}

fn normalize_mac(value: &str) -> Result<String> {
    let compact = value
        .trim()
        .replace('-', ":")
        .split(':')
        .collect::<Vec<_>>()
        .join("")
        .to_ascii_lowercase();
    if compact.len() != 12 || !compact.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("wired interface has an invalid MAC address")
    }
    Ok((0..6)
        .map(|index| compact[index * 2..index * 2 + 2].to_string())
        .collect::<Vec<_>>()
        .join(":"))
}

fn parse_ipv4_cidr(value: &str) -> Result<(Ipv4Addr, u8)> {
    let (address, prefix) = value
        .split_once('/')
        .ok_or_else(|| anyhow!("static address must use IPv4 CIDR notation"))?;
    let address = address.parse().context("static IPv4 address is invalid")?;
    let prefix: u8 = prefix.parse().context("static IPv4 prefix is invalid")?;
    if !(1..=32).contains(&prefix) {
        bail!("static IPv4 prefix is invalid")
    }
    Ok((address, prefix))
}

fn same_ipv4_subnet(left: Ipv4Addr, right: Ipv4Addr, prefix: u8) -> bool {
    let mask = u32::MAX.checked_shl((32 - prefix).into()).unwrap_or(0);
    u32::from(left) & mask == u32::from(right) & mask
}

fn canonical_json(value: Value) -> Value {
    match value {
        Value::Object(object) => {
            let sorted = object
                .into_iter()
                .map(|(key, value)| (key, canonical_json(value)))
                .collect::<BTreeMap<_, _>>();
            Value::Object(sorted.into_iter().collect())
        }
        Value::Array(values) => Value::Array(values.into_iter().map(canonical_json).collect()),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stable_inventory_fixture() -> PulseProvisioningInventory {
        PulseProvisioningInventory {
            manufacturer: "Cybex".into(),
            model: "Qualification VM".into(),
            serial_number: "vm-1".into(),
            asset_tag: "lab".into(),
            cpu_model: "test cpu".into(),
            cpu_cores: 4,
            memory_bytes: 32 * 1024 * 1024 * 1024,
            firmware_version: "firmware-a".into(),
            kernel_version: "kernel-a".into(),
            boot_mode: "uefi".into(),
            secure_boot: true,
            virtualization: "kvm".into(),
            ethernet_interfaces: vec![PulseProvisioningEthernetInterface {
                id: "pci-0000:00:03.0".into(),
                name: "enp0s3".into(),
                mac: "52:54:00:12:34:56".into(),
                link_up: true,
                addresses: vec!["10.62.52.76/24".into()],
                gateway: Some("10.62.52.1".into()),
            }],
            disks: vec![PulseProvisioningDisk {
                id: "scsi-qualification".into(),
                path: "/dev/sda".into(),
                model: "QEMU disk".into(),
                serial: "disk-1".into(),
                wwn: String::new(),
                size_bytes: 160 * 1024 * 1024 * 1024,
                removable: false,
                mounted: false,
                held: false,
                eligible: true,
                blocker_codes: Vec::new(),
            }],
        }
    }

    #[test]
    fn stable_hardware_digest_ignores_volatile_network_and_software_inventory() {
        let inventory = stable_inventory_fixture();
        let expected = hardware_digest(&inventory).unwrap();
        let mut changed = inventory.clone();
        changed.ethernet_interfaces[0].addresses = vec!["10.62.52.99/24".into()];
        changed.ethernet_interfaces[0].gateway = Some("10.62.52.254".into());
        changed.firmware_version = "firmware-b".into();
        changed.kernel_version = "kernel-b".into();
        assert_eq!(hardware_digest(&changed).unwrap(), expected);

        changed.memory_bytes += 1024 * 1024 * 1024;
        assert_ne!(hardware_digest(&changed).unwrap(), expected);
    }

    #[test]
    fn subnet_validation_is_exact() {
        assert!(same_ipv4_subnet(
            "192.0.2.10".parse().unwrap(),
            "192.0.2.1".parse().unwrap(),
            24
        ));
        assert!(!same_ipv4_subnet(
            "192.0.2.10".parse().unwrap(),
            "192.0.3.1".parse().unwrap(),
            24
        ));
    }

    #[test]
    fn management_connectivity_probe_accepts_only_a_bare_https_origin() {
        assert_eq!(
            manage_https_host("https://manage.cybex.net").unwrap(),
            "manage.cybex.net"
        );
        for invalid in [
            "http://manage.cybex.net",
            "https://manage.cybex.net:8443",
            "https://user@manage.cybex.net",
            "https://manage.cybex.net/path",
            "https://manage.cybex.net?query=yes",
        ] {
            assert!(manage_https_host(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn static_network_route_uses_the_approved_subnet() {
        assert_eq!(
            ipv4_network("192.0.2.129".parse().unwrap(), 25),
            "192.0.2.128".parse::<Ipv4Addr>().unwrap()
        );
    }

    #[test]
    fn removable_or_small_disks_cannot_be_eligible() {
        let disk = PulseProvisioningDisk {
            id: "ata-test".into(),
            path: "/dev/sda".into(),
            model: String::new(),
            serial: String::new(),
            wwn: String::new(),
            size_bytes: MIN_DISK_BYTES - 1,
            removable: false,
            mounted: false,
            held: false,
            eligible: false,
            blocker_codes: vec!["disk_too_small".into()],
        };
        assert!(!disk.eligible);
    }
}
