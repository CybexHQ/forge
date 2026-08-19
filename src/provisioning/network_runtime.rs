use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    net::Ipv4Addr,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
};

const MAX_NETWORK_PLAN_BYTES: u64 = 1024 * 1024;
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Debug)]
pub struct NetworkRuntimeOptions {
    pub config_path: PathBuf,
    pub network_plan_path: PathBuf,
    pub fallback_network_plan_path: PathBuf,
    pub fallback_marker_path: PathBuf,
    ip_binary: PathBuf,
    sys_class_net_root: PathBuf,
}

impl Default for NetworkRuntimeOptions {
    fn default() -> Self {
        Self {
            config_path: PathBuf::from("/etc/cybex-james/config.toml"),
            network_plan_path: PathBuf::from("/var/lib/cybex-james/control/netplan-approved.json"),
            fallback_network_plan_path: PathBuf::from(
                "/var/lib/cybex-james/control/netplan-dhcp-fallback.json",
            ),
            fallback_marker_path: PathBuf::from(
                "/var/lib/cybex-james/control/network-fallback-active",
            ),
            ip_binary: PathBuf::from("/usr/sbin/ip"),
            sys_class_net_root: PathBuf::from("/sys/class/net"),
        }
    }
}

impl NetworkRuntimeOptions {
    pub fn new(config_path: PathBuf, network_plan_path: PathBuf) -> Self {
        Self {
            config_path,
            network_plan_path,
            ..Self::default()
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkRuntimeOutcome {
    Changed,
    Unchanged,
}

impl NetworkRuntimeOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Changed => "changed",
            Self::Unchanged => "unchanged",
        }
    }
}

#[derive(Debug, Deserialize)]
struct ApprovedNetplan {
    network: ApprovedNetplanNetwork,
}

#[derive(Debug, Deserialize)]
struct ApprovedNetplanNetwork {
    version: u8,
    renderer: String,
    ethernets: BTreeMap<String, ApprovedNetplanInterface>,
}

#[derive(Debug, Deserialize)]
struct ApprovedNetplanInterface {
    #[serde(rename = "match")]
    interface_match: ApprovedNetplanMatch,
    #[serde(rename = "set-name")]
    set_name: String,
    dhcp4: bool,
    dhcp6: bool,
    #[serde(default)]
    addresses: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ApprovedNetplanMatch {
    macaddress: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkFallbackMarker {
    schema: String,
    approved_sha256: String,
}

struct ApprovedRuntimeNetwork {
    interface_name: String,
    interface_mac: String,
    mode: &'static str,
    address_cidr: Option<String>,
}

#[derive(Debug, Deserialize)]
struct IpAddressDevice {
    #[serde(default)]
    addr_info: Vec<IpAddressInfo>,
}

#[derive(Debug, Deserialize)]
struct IpAddressInfo {
    family: String,
    local: String,
    scope: String,
    #[serde(default)]
    flags: Vec<String>,
    #[serde(default)]
    preferred_life_time: serde_json::Value,
}

pub fn reconcile_network_runtime(options: NetworkRuntimeOptions) -> Result<NetworkRuntimeOutcome> {
    // netplan-approved.json is written during signed installation and replaced
    // only after Management has acknowledged a verified network change. Unlike
    // the immutable install plan, it therefore remains the durable source of
    // truth after an operator intentionally changes address or interface.
    let network_plan_path = selected_network_plan_path(&options)?;
    let plan: ApprovedNetplan = read_bounded_json(
        network_plan_path,
        MAX_NETWORK_PLAN_BYTES,
        "active James network plan",
    )?;
    let network = approved_runtime_network(&plan)?;
    validate_interface_name(&network.interface_name)?;
    let expected_mac = normalize_mac(&network.interface_mac)?;
    let actual_mac_path = options
        .sys_class_net_root
        .join(&network.interface_name)
        .join("address");
    let actual_mac = fs::read_to_string(&actual_mac_path).with_context(|| {
        format!(
            "read managed interface identity from {}",
            actual_mac_path.display()
        )
    })?;
    if normalize_mac(&actual_mac)? != expected_mac {
        bail!("managed network interface identity changed")
    }

    let output = Command::new(&options.ip_binary)
        .args([
            "-j",
            "-4",
            "address",
            "show",
            "dev",
            &network.interface_name,
            "scope",
            "global",
        ])
        .output()
        .with_context(|| format!("run {} for managed interface", options.ip_binary.display()))?;
    if !output.status.success() || output.stdout.len() as u64 > MAX_NETWORK_PLAN_BYTES {
        bail!("managed interface address discovery failed")
    }
    let devices: Vec<IpAddressDevice> =
        serde_json::from_slice(&output.stdout).context("parse managed interface addresses")?;
    let addresses = eligible_ipv4_addresses(&devices)?;
    let selected = select_runtime_ipv4(network.mode, network.address_cidr.as_deref(), &addresses)?;
    let desired = format!("http://{selected}");

    let mut config = read_bounded_regular_file(
        &options.config_path,
        MAX_CONFIG_BYTES,
        "James configuration",
    )?;
    let parsed = crate::config::AppConfig::from_toml_str(&config, &options.config_path)
        .context("validate James configuration before network reconciliation")?;
    if parsed.public_base_url() == desired {
        parsed
            .validate_appliance_config()
            .context("validate installed appliance configuration")?;
        return Ok(NetworkRuntimeOutcome::Unchanged);
    }
    config = replace_server_public_base_url(&config, &desired)?;
    crate::config::AppConfig::from_toml_str(&config, &options.config_path)
        .context("validate reconciled James configuration")?
        .validate_appliance_config()
        .context("validate installed appliance configuration")?;
    atomic_replace_preserving_metadata(&options.config_path, config.as_bytes())?;
    Ok(NetworkRuntimeOutcome::Changed)
}

pub fn network_fallback_active() -> Result<bool> {
    fallback_marker_applies(&NetworkRuntimeOptions::default())
}

fn selected_network_plan_path(options: &NetworkRuntimeOptions) -> Result<&Path> {
    Ok(network_plan_path_for_fallback(
        options,
        fallback_marker_applies(options)?,
    ))
}

fn fallback_marker_applies(options: &NetworkRuntimeOptions) -> Result<bool> {
    match fs::symlink_metadata(&options.fallback_marker_path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file()
                || metadata.len() == 0
                || metadata.len() > 256
                || metadata.nlink() != 1
                || metadata.uid() != 0
                || metadata.mode() & 0o077 != 0
            {
                bail!("James network fallback marker is not a trusted root-owned file")
            }
            let marker: NetworkFallbackMarker = read_bounded_json(
                &options.fallback_marker_path,
                256,
                "James network fallback marker",
            )?;
            let approved = read_bounded_regular_file(
                &options.network_plan_path,
                MAX_NETWORK_PLAN_BYTES,
                "approved James network plan",
            )?;
            fallback_marker_matches_approved(&marker, approved.as_bytes())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).context("inspect James network fallback marker"),
    }
}

fn fallback_marker_matches_approved(
    marker: &NetworkFallbackMarker,
    approved: &[u8],
) -> Result<bool> {
    if marker.schema != "cybex.james.network-fallback.v1"
        || marker.approved_sha256.len() != 64
        || !marker
            .approved_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("James network fallback marker is invalid")
    }
    Ok(hex::encode(Sha256::digest(approved)) == marker.approved_sha256)
}

fn network_plan_path_for_fallback(options: &NetworkRuntimeOptions, fallback_active: bool) -> &Path {
    if fallback_active {
        &options.fallback_network_plan_path
    } else {
        &options.network_plan_path
    }
}

fn approved_runtime_network(plan: &ApprovedNetplan) -> Result<ApprovedRuntimeNetwork> {
    if plan.network.version != 2 || plan.network.renderer != "networkd" {
        bail!("approved James network plan has an unsupported network shape")
    }
    if plan.network.ethernets.len() != 1 {
        bail!("approved James network plan must contain exactly one wired interface")
    }
    let interface = plan
        .network
        .ethernets
        .get("cybex-james")
        .ok_or_else(|| anyhow!("approved James network plan omitted its managed interface"))?;
    if interface.dhcp6 {
        bail!("approved James network plan must keep DHCPv6 disabled")
    }
    let (mode, address_cidr) = if interface.dhcp4 {
        if !interface.addresses.is_empty() {
            bail!("approved DHCP plan must not contain static addresses")
        }
        ("dhcp", None)
    } else {
        match interface.addresses.as_slice() {
            [address] => ("static", Some(address.clone())),
            _ => bail!("approved static plan must contain exactly one IPv4 address"),
        }
    };
    Ok(ApprovedRuntimeNetwork {
        interface_name: interface.set_name.clone(),
        interface_mac: interface.interface_match.macaddress.clone(),
        mode,
        address_cidr,
    })
}

fn eligible_ipv4_addresses(devices: &[IpAddressDevice]) -> Result<Vec<Ipv4Addr>> {
    let mut addresses = Vec::new();
    for info in devices.iter().flat_map(|device| &device.addr_info) {
        if info.family != "inet"
            || info.scope != "global"
            || info.flags.iter().any(|flag| {
                matches!(
                    flag.as_str(),
                    "tentative" | "dadfailed" | "deprecated" | "secondary"
                )
            })
            || preferred_lifetime_expired(&info.preferred_life_time)
        {
            continue;
        }
        let address: Ipv4Addr = info
            .local
            .parse()
            .context("managed interface reported an invalid IPv4 address")?;
        if address.is_loopback()
            || address.is_link_local()
            || address.is_multicast()
            || address.is_unspecified()
            || address.octets() == [255, 255, 255, 255]
        {
            continue;
        }
        if !addresses.contains(&address) {
            addresses.push(address);
        }
    }
    addresses.sort_unstable();
    Ok(addresses)
}

fn preferred_lifetime_expired(value: &serde_json::Value) -> bool {
    value.as_u64() == Some(0) || value.as_str() == Some("0sec")
}

fn select_runtime_ipv4(
    mode: &str,
    address_cidr: Option<&str>,
    addresses: &[Ipv4Addr],
) -> Result<Ipv4Addr> {
    match mode {
        "dhcp" => match addresses {
            [address] => Ok(*address),
            [] => bail!("managed DHCP interface has no usable IPv4 address"),
            _ => bail!("managed DHCP interface has multiple primary IPv4 addresses"),
        },
        "static" => {
            let (address, prefix) = address_cidr
                .and_then(|cidr| cidr.split_once('/'))
                .ok_or_else(|| anyhow!("static network plan omitted its IPv4 address"))?;
            let expected: Ipv4Addr = address
                .parse()
                .context("static network plan contains an invalid IPv4 address")?;
            let prefix: u8 = prefix
                .parse()
                .context("static network plan contains an invalid IPv4 prefix")?;
            if prefix > 32 {
                bail!("static network plan contains an invalid IPv4 prefix")
            }
            if !addresses.contains(&expected) {
                bail!("managed static IPv4 address is not active")
            }
            Ok(expected)
        }
        _ => bail!("installed network plan mode is invalid"),
    }
}

fn replace_server_public_base_url(config: &str, desired: &str) -> Result<String> {
    let replacement = format!(
        "public_base_url = {}",
        serde_json::to_string(desired).expect("URL string is valid JSON and TOML")
    );
    let mut in_server = false;
    let mut replaced = 0;
    let mut output = String::with_capacity(config.len() + desired.len());
    for raw_line in config.split_inclusive('\n') {
        let line = raw_line.strip_suffix('\n').unwrap_or(raw_line);
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_server = trimmed == "[server]";
        }
        if in_server && trimmed.starts_with("public_base_url") {
            let key = trimmed.split('=').next().unwrap_or_default().trim();
            if key != "public_base_url" {
                bail!("James server public URL declaration is malformed")
            }
            output.push_str(&replacement);
            if raw_line.ends_with('\n') {
                output.push('\n');
            }
            replaced += 1;
        } else {
            output.push_str(raw_line);
        }
    }
    if replaced != 1 {
        bail!("James configuration must contain one server public URL")
    }
    Ok(output)
}

fn read_bounded_json<T: for<'de> Deserialize<'de>>(
    path: &Path,
    limit: u64,
    label: &str,
) -> Result<T> {
    let body = read_bounded_regular_file(path, limit, label)?;
    serde_json::from_str(&body).with_context(|| format!("parse {label}"))
}

fn read_bounded_regular_file(path: &Path, limit: u64, label: &str) -> Result<String> {
    let metadata = fs::symlink_metadata(path).with_context(|| format!("inspect {label}"))?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > limit {
        bail!("{label} must be a bounded non-empty regular file")
    }
    fs::read_to_string(path).with_context(|| format!("read {label}"))
}

fn atomic_replace_preserving_metadata(path: &Path, body: &[u8]) -> Result<()> {
    let metadata = fs::symlink_metadata(path).context("inspect James configuration metadata")?;
    if !metadata.file_type().is_file() {
        bail!("James configuration must be a regular file")
    }
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("James configuration has no parent directory"))?;
    let temporary = parent.join(format!(
        ".network-runtime.{}.tmp",
        uuid::Uuid::new_v4().simple()
    ));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(metadata.mode() & 0o7777)
            .open(&temporary)
            .context("create temporary James configuration")?;
        let owner_status = unsafe {
            use std::os::fd::AsRawFd;
            libc::fchown(file.as_raw_fd(), metadata.uid(), metadata.gid())
        };
        if owner_status != 0 {
            return Err(std::io::Error::last_os_error()).context("preserve James config owner");
        }
        file.set_permissions(fs::Permissions::from_mode(metadata.mode() & 0o7777))?;
        file.write_all(body)?;
        file.sync_all()?;
        fs::rename(&temporary, path).context("activate reconciled James configuration")?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn validate_interface_name(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 64
        || value.starts_with(['-', '.'])
        || value.contains("..")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        bail!("managed interface name is invalid")
    }
    Ok(())
}

fn normalize_mac(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase().replace('-', ":");
    let parts = normalized.split(':').collect::<Vec<_>>();
    if parts.len() != 6
        || parts
            .iter()
            .any(|part| part.len() != 2 || !part.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        bail!("managed interface MAC address is invalid")
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dhcp_requires_one_current_primary_address() {
        assert_eq!(
            select_runtime_ipv4("dhcp", None, &[Ipv4Addr::new(10, 20, 30, 40)]).unwrap(),
            Ipv4Addr::new(10, 20, 30, 40)
        );
        assert!(select_runtime_ipv4("dhcp", None, &[]).is_err());
        assert!(
            select_runtime_ipv4(
                "dhcp",
                None,
                &[Ipv4Addr::new(10, 20, 30, 40), Ipv4Addr::new(10, 20, 30, 41)]
            )
            .is_err()
        );
    }

    #[test]
    fn static_address_must_be_active() {
        let active = Ipv4Addr::new(192, 0, 2, 20);
        assert_eq!(
            select_runtime_ipv4("static", Some("192.0.2.20/24"), &[active]).unwrap(),
            active
        );
        assert!(select_runtime_ipv4("static", Some("192.0.2.21/24"), &[active]).is_err());
    }

    #[test]
    fn address_inventory_ignores_unsafe_and_secondary_addresses() {
        let devices: Vec<IpAddressDevice> = serde_json::from_value(serde_json::json!([{
            "addr_info": [
                {"family":"inet","local":"169.254.1.2","scope":"global"},
                {"family":"inet","local":"10.0.0.3","scope":"global","flags":["secondary"]},
                {"family":"inet","local":"10.0.0.2","scope":"global","preferred_life_time":3600},
                {"family":"inet6","local":"2001:db8::1","scope":"global"}
            ]
        }]))
        .unwrap();
        assert_eq!(
            eligible_ipv4_addresses(&devices).unwrap(),
            vec![Ipv4Addr::new(10, 0, 0, 2)]
        );
    }

    #[test]
    fn approved_netplan_becomes_the_runtime_source_of_truth() {
        let plan: ApprovedNetplan = serde_json::from_value(serde_json::json!({
            "network": {
                "version": 2,
                "renderer": "networkd",
                "ethernets": {
                    "cybex-james": {
                        "match": {"macaddress": "02:00:00:00:00:42"},
                        "set-name": "enp2s0",
                        "dhcp4": false,
                        "dhcp6": false,
                        "addresses": ["192.0.2.42/24"],
                        "routes": [{"to": "default", "via": "192.0.2.1"}]
                    }
                }
            }
        }))
        .unwrap();

        let runtime = approved_runtime_network(&plan).unwrap();
        assert_eq!(runtime.interface_name, "enp2s0");
        assert_eq!(runtime.interface_mac, "02:00:00:00:00:42");
        assert_eq!(runtime.mode, "static");
        assert_eq!(runtime.address_cidr.as_deref(), Some("192.0.2.42/24"));
    }

    #[test]
    fn active_fallback_selects_the_durable_dhcp_plan() {
        let options = NetworkRuntimeOptions::default();

        assert_eq!(
            network_plan_path_for_fallback(&options, false),
            options.network_plan_path
        );
        assert_eq!(
            network_plan_path_for_fallback(&options, true),
            options.fallback_network_plan_path
        );
    }

    #[test]
    fn stale_fallback_marker_cannot_override_newly_approved_plan() {
        let old_approved = br#"{"network":{"version":2,"approved":"old"}}"#;
        let new_approved = br#"{"network":{"version":2,"approved":"new"}}"#;
        let marker = NetworkFallbackMarker {
            schema: "cybex.james.network-fallback.v1".to_string(),
            approved_sha256: hex::encode(Sha256::digest(old_approved)),
        };

        assert!(fallback_marker_matches_approved(&marker, old_approved).unwrap());
        assert!(!fallback_marker_matches_approved(&marker, new_approved).unwrap());
    }

    #[test]
    fn only_the_server_public_url_is_replaced() {
        let input = "[server]\nlisten_addr = \"127.0.0.1:8080\"\npublic_base_url = \"http://10.0.0.2\"\n\n[manage]\napi_url = \"https://manage.example\"\n";
        let output = replace_server_public_base_url(input, "http://10.0.0.3").unwrap();
        assert!(output.contains("public_base_url = \"http://10.0.0.3\""));
        assert!(output.contains("api_url = \"https://manage.example\""));
        assert!(!output.contains("10.0.0.2"));
    }
}
