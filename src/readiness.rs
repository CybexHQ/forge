use std::{
    fs::OpenOptions,
    future::Future,
    io::Read,
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

use reqwest::{Client, ClientBuilder, Url, redirect::Policy};
use tokio::{net::UdpSocket, sync::watch, time::timeout};

use crate::{AppState, RuntimeSettings};

const MIN_EFI_BOOTLOADER_BYTES: u64 = 32 * 1024;
const MAX_EFI_BOOTLOADER_BYTES: u64 = 4 * 1024 * 1024;
const MIN_IPXE_AUTOEXEC_BYTES: u64 = 64;
const MAX_IPXE_AUTOEXEC_BYTES: u64 = 4 * 1024;
const MAX_BOOT_CHECK_BYTES: usize = 64 * 1024;
const TFTP_ROOT: &str = "/var/cache/cybex-james/tftp";
const IPXE_AUTOEXEC_FILENAME: &str = "autoexec.ipxe";
const IPXE_AUTOEXEC_PACKAGE_PATH: &str = "/usr/share/cybex-james/autoexec.ipxe";
const IPXE_AUTOEXEC_BODY: &[u8] =
    include_bytes!("../ubuntu-appliance/rootfs/usr/share/cybex-james/autoexec.ipxe");
const READINESS_TIMEOUT: Duration = Duration::from_secs(3);
const READINESS_POSITIVE_CACHE_TTL: Duration = Duration::from_secs(20);
// Degraded health remains rate-limited because each uncached check reads and
// transfers the complete bootloader, while still recovering four times faster
// than the normal positive cache window during appliance startup.
const READINESS_NEGATIVE_CACHE_TTL: Duration = Duration::from_secs(5);
const READINESS_STALE_TTL: Duration = Duration::from_secs(60);
const READINESS_FOLLOWER_WAIT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug)]
pub struct ApplianceReadiness {
    pub ready: bool,
    pub appliance_config: bool,
    pub bootloader_asset: bool,
    pub tftp_bootloader: bool,
    pub ipxe_chain_script_asset: bool,
    pub tftp_ipxe_chain_script: bool,
    pub public_boot_url: bool,
}

impl ApplianceReadiness {
    fn standalone() -> Self {
        Self {
            ready: true,
            appliance_config: true,
            bootloader_asset: true,
            tftp_bootloader: true,
            ipxe_chain_script_asset: true,
            tftp_ipxe_chain_script: true,
            public_boot_url: true,
        }
    }

    fn unavailable() -> Self {
        Self {
            ready: false,
            appliance_config: false,
            bootloader_asset: false,
            tftp_bootloader: false,
            ipxe_chain_script_asset: false,
            tftp_ipxe_chain_script: false,
            public_boot_url: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReadinessKey {
    public_base_url: String,
    bootloader_filename: String,
}

impl From<&RuntimeSettings> for ReadinessKey {
    fn from(runtime: &RuntimeSettings) -> Self {
        Self {
            public_base_url: runtime.public_base_url.clone(),
            bootloader_filename: runtime.bootloader_filename.clone(),
        }
    }
}

struct CachedReadiness {
    probe_id: u64,
    key: ReadinessKey,
    checked_at: Instant,
    result: ApplianceReadiness,
}

#[derive(Clone)]
struct InFlightProbe {
    id: u64,
    key: ReadinessKey,
}

#[derive(Default)]
struct ReadinessCacheState {
    result: Option<CachedReadiness>,
    in_flight: Option<InFlightProbe>,
    next_probe_id: u64,
}

struct ReadinessCache {
    state: Mutex<ReadinessCacheState>,
    completion: watch::Sender<u64>,
}

impl Default for ReadinessCache {
    fn default() -> Self {
        let (completion, _) = watch::channel(0);
        Self {
            state: Mutex::new(ReadinessCacheState::default()),
            completion,
        }
    }
}

impl ReadinessCache {
    async fn get_or_probe<F, Fut>(&self, key: ReadinessKey, probe: F) -> ApplianceReadiness
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = ApplianceReadiness>,
    {
        let mut probe = Some(probe);
        loop {
            // Subscribe before inspecting the lease so a completion between
            // dropping the mutex and awaiting the watch channel is retained.
            let mut completion = self.completion.subscribe();
            let decision = {
                let mut state = self
                    .state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if let Some(result) = fresh_result(state.result.as_ref(), &key) {
                    return result;
                }
                if let Some(in_flight) = state.in_flight.as_ref() {
                    if in_flight.key == key {
                        if let Some(result) = stale_positive_result(state.result.as_ref(), &key) {
                            return result;
                        }
                    }
                    ProbeDecision::Follow(in_flight.id)
                } else {
                    state.next_probe_id = state.next_probe_id.wrapping_add(1).max(1);
                    let probe_id = state.next_probe_id;
                    state.in_flight = Some(InFlightProbe {
                        id: probe_id,
                        key: key.clone(),
                    });
                    ProbeDecision::Lead(probe_id)
                }
            };

            match decision {
                ProbeDecision::Lead(probe_id) => {
                    let mut guard = ProbeGuard::new(self, probe_id);
                    let result = probe.take().expect("readiness probe launched once")().await;
                    {
                        let mut state = self
                            .state
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                        if state
                            .in_flight
                            .as_ref()
                            .is_some_and(|in_flight| in_flight.id == probe_id)
                        {
                            state.result = Some(CachedReadiness {
                                probe_id,
                                key,
                                checked_at: Instant::now(),
                                result: result.clone(),
                            });
                            state.in_flight = None;
                        }
                    }
                    guard.disarm();
                    self.notify_completion();
                    return result;
                }
                ProbeDecision::Follow(probe_id) => {
                    let completed = timeout(READINESS_FOLLOWER_WAIT, completion.changed())
                        .await
                        .is_ok();
                    let state = self
                        .state
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    if let Some(cached) = state
                        .result
                        .as_ref()
                        .filter(|cached| cached.probe_id == probe_id && cached.key == key)
                    {
                        return cached.result.clone();
                    }
                    if !completed {
                        if let Some(result) = stale_positive_result(state.result.as_ref(), &key) {
                            return result;
                        }
                        // The real probe exceeded its own I/O deadline plus a
                        // scheduling margin. This is a probe timeout, not a
                        // synthetic contention failure.
                        return ApplianceReadiness::unavailable();
                    }
                    drop(state);
                    // A different-key probe completed or a leader was
                    // cancelled. Re-evaluate and acquire the now-free lease.
                }
            }
        }
    }

    fn notify_completion(&self) {
        self.completion
            .send_modify(|generation| *generation = generation.wrapping_add(1));
    }
}

enum ProbeDecision {
    Lead(u64),
    Follow(u64),
}

fn fresh_result(
    cached: Option<&CachedReadiness>,
    key: &ReadinessKey,
) -> Option<ApplianceReadiness> {
    let cached = cached.filter(|cached| cached.key == *key)?;
    let ttl = if cached.result.ready {
        READINESS_POSITIVE_CACHE_TTL
    } else {
        READINESS_NEGATIVE_CACHE_TTL
    };
    (cached.checked_at.elapsed() <= ttl).then(|| cached.result.clone())
}

fn stale_positive_result(
    cached: Option<&CachedReadiness>,
    key: &ReadinessKey,
) -> Option<ApplianceReadiness> {
    cached
        .filter(|cached| {
            cached.key == *key
                && cached.result.ready
                && cached.checked_at.elapsed() <= READINESS_STALE_TTL
        })
        .map(|cached| cached.result.clone())
}

struct ProbeGuard<'a> {
    cache: &'a ReadinessCache,
    probe_id: u64,
    armed: bool,
}

impl<'a> ProbeGuard<'a> {
    fn new(cache: &'a ReadinessCache, probe_id: u64) -> Self {
        Self {
            cache,
            probe_id,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ProbeGuard<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut state = self
            .cache
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state
            .in_flight
            .as_ref()
            .is_some_and(|in_flight| in_flight.id == self.probe_id)
        {
            state.in_flight = None;
        }
        drop(state);
        self.cache.notify_completion();
    }
}

static READINESS_CACHE: OnceLock<ReadinessCache> = OnceLock::new();

pub async fn probe(state: &AppState) -> ApplianceReadiness {
    if !crate::appliance::is_managed_ubuntu() {
        return ApplianceReadiness::standalone();
    }
    let runtime = state.runtime_settings();
    let key = ReadinessKey::from(&runtime);
    READINESS_CACHE
        .get_or_init(ReadinessCache::default)
        .get_or_probe(key, || probe_uncached(state, runtime))
        .await
}

pub(crate) async fn probe_fresh(state: &AppState) -> ApplianceReadiness {
    if !crate::appliance::is_managed_ubuntu() {
        return ApplianceReadiness::standalone();
    }
    probe_uncached(state, state.runtime_settings()).await
}

async fn probe_uncached(state: &AppState, runtime: RuntimeSettings) -> ApplianceReadiness {
    let appliance_config = state.config.validate_appliance_config().is_ok();
    let package_path = package_bootloader_path(&runtime.bootloader_filename);
    let bootloader = package_path.and_then(read_valid_bootloader);
    let bootloader_asset = bootloader.is_some();
    let ipxe_chain_script = read_valid_ipxe_chain_script(Path::new(IPXE_AUTOEXEC_PACKAGE_PATH));
    let ipxe_chain_script_asset = ipxe_chain_script.is_some();
    let staged_bootloader = bootloader.as_deref().and_then(|expected| {
        read_safe_public_tftp_bootloader(Path::new(TFTP_ROOT), &runtime.bootloader_filename, 0, 0)
            .filter(|actual| actual == expected)
    });
    let staged_ipxe_chain_script = ipxe_chain_script.as_deref().and_then(|expected| {
        read_safe_public_tftp_ipxe_chain_script(Path::new(TFTP_ROOT), 0, 0)
            .filter(|actual| actual == expected)
    });
    let (tftp_bootloader, tftp_ipxe_chain_script, public_boot_url) = tokio::join!(
        async {
            if let Some(expected) = staged_bootloader.as_deref() {
                tftp_serves_expected_bootloader(
                    "127.0.0.1:69".parse().expect("literal TFTP address"),
                    &runtime.bootloader_filename,
                    expected,
                )
                .await
            } else {
                false
            }
        },
        async {
            if let Some(expected) = staged_ipxe_chain_script.as_deref() {
                tftp_serves_expected_bootloader(
                    "127.0.0.1:69".parse().expect("literal TFTP address"),
                    IPXE_AUTOEXEC_FILENAME,
                    expected,
                )
                .await
            } else {
                false
            }
        },
        public_boot_url_reachable(&runtime.public_base_url),
    );
    let ready = appliance_config
        && bootloader_asset
        && tftp_bootloader
        && ipxe_chain_script_asset
        && tftp_ipxe_chain_script
        && public_boot_url;
    ApplianceReadiness {
        ready,
        appliance_config,
        bootloader_asset,
        tftp_bootloader,
        ipxe_chain_script_asset,
        tftp_ipxe_chain_script,
        public_boot_url,
    }
}

fn package_bootloader_path(filename: &str) -> Option<&'static Path> {
    match filename {
        "snponly.efi" => Some(Path::new("/usr/lib/ipxe/snponly.efi")),
        "ipxe.efi" => Some(Path::new("/usr/lib/ipxe/ipxe-amd64.efi")),
        _ => None,
    }
}

fn read_valid_bootloader(path: &Path) -> Option<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.file_type().is_file()
        || metadata.len() < MIN_EFI_BOOTLOADER_BYTES
        || metadata.len() > MAX_EFI_BOOTLOADER_BYTES
    {
        return None;
    }
    let mut body = Vec::with_capacity(metadata.len() as usize);
    file.by_ref()
        .take(MAX_EFI_BOOTLOADER_BYTES + 1)
        .read_to_end(&mut body)
        .ok()?;
    (body.len() as u64 == metadata.len() && validate_x86_64_efi_application(&body)).then_some(body)
}

fn read_valid_ipxe_chain_script(path: &Path) -> Option<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.permissions().mode() & 0o777 != 0o644
        || metadata.len() < MIN_IPXE_AUTOEXEC_BYTES
        || metadata.len() > MAX_IPXE_AUTOEXEC_BYTES
    {
        return None;
    }
    let mut body = Vec::with_capacity(metadata.len() as usize);
    file.by_ref()
        .take(MAX_IPXE_AUTOEXEC_BYTES + 1)
        .read_to_end(&mut body)
        .ok()?;
    (body.len() as u64 == metadata.len() && body == IPXE_AUTOEXEC_BODY).then_some(body)
}

/// Read one immutable public TFTP launcher only after proving the containing
/// root and file have the exact ownership/modes expected by tftpd-hpa. The
/// public-readability bit is intentional; root-only ownership and directory
/// write permissions keep both service accounts unable to replace the bytes.
fn read_safe_public_tftp_bootloader(
    root: &Path,
    filename: &str,
    required_uid: u32,
    required_gid: u32,
) -> Option<Vec<u8>> {
    if !matches!(filename, "snponly.efi" | "ipxe.efi") {
        return None;
    }
    let root_metadata = std::fs::symlink_metadata(root).ok()?;
    if !root_metadata.file_type().is_dir()
        || root_metadata.uid() != required_uid
        || root_metadata.gid() != required_gid
        || root_metadata.permissions().mode() & 0o777 != 0o755
    {
        return None;
    }
    let path = root.join(filename);
    let metadata = std::fs::symlink_metadata(&path).ok()?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.uid() != required_uid
        || metadata.gid() != required_gid
        || metadata.permissions().mode() & 0o777 != 0o644
    {
        return None;
    }
    read_valid_bootloader(&path)
}

fn read_safe_public_tftp_ipxe_chain_script(
    root: &Path,
    required_uid: u32,
    required_gid: u32,
) -> Option<Vec<u8>> {
    let root_metadata = std::fs::symlink_metadata(root).ok()?;
    if !root_metadata.file_type().is_dir()
        || root_metadata.uid() != required_uid
        || root_metadata.gid() != required_gid
        || root_metadata.permissions().mode() & 0o777 != 0o755
    {
        return None;
    }
    let path = root.join(IPXE_AUTOEXEC_FILENAME);
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.uid() != required_uid
        || metadata.gid() != required_gid
        || metadata.permissions().mode() & 0o777 != 0o644
        || metadata.len() < MIN_IPXE_AUTOEXEC_BYTES
        || metadata.len() > MAX_IPXE_AUTOEXEC_BYTES
    {
        return None;
    }
    let mut body = Vec::with_capacity(metadata.len() as usize);
    file.by_ref()
        .take(MAX_IPXE_AUTOEXEC_BYTES + 1)
        .read_to_end(&mut body)
        .ok()?;
    (body.len() as u64 == metadata.len() && body == IPXE_AUTOEXEC_BODY).then_some(body)
}

fn validate_x86_64_efi_application(body: &[u8]) -> bool {
    if body.len() < 0x40 || &body[..2] != b"MZ" {
        return false;
    }
    let pe_offset = u32::from_le_bytes(body[0x3c..0x40].try_into().unwrap()) as usize;
    let Some(optional_offset) = pe_offset.checked_add(24) else {
        return false;
    };
    let Some(subsystem_offset) = optional_offset.checked_add(68) else {
        return false;
    };
    let Some(required) = subsystem_offset.checked_add(2) else {
        return false;
    };
    if required > body.len()
        || pe_offset.saturating_add(6) > body.len()
        || optional_offset.saturating_add(2) > body.len()
        || &body[pe_offset..pe_offset + 4] != b"PE\0\0"
    {
        return false;
    }
    let machine = u16::from_le_bytes(body[pe_offset + 4..pe_offset + 6].try_into().unwrap());
    let optional_magic = u16::from_le_bytes(
        body[optional_offset..optional_offset + 2]
            .try_into()
            .unwrap(),
    );
    let subsystem = u16::from_le_bytes(
        body[subsystem_offset..subsystem_offset + 2]
            .try_into()
            .unwrap(),
    );
    machine == 0x8664 && optional_magic == 0x20b && subsystem == 10
}

async fn tftp_serves_expected_bootloader(
    server: SocketAddr,
    filename: &str,
    expected: &[u8],
) -> bool {
    timeout(
        READINESS_TIMEOUT,
        tftp_transfer_matches(server, filename, expected),
    )
    .await
    .unwrap_or(false)
}

async fn tftp_transfer_matches(server: SocketAddr, filename: &str, expected: &[u8]) -> bool {
    if filename.is_empty()
        || filename.len() > 128
        || expected.is_empty()
        || expected.len() > MAX_EFI_BOOTLOADER_BYTES as usize
        || !filename
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return false;
    }
    let Ok(socket) = UdpSocket::bind("127.0.0.1:0").await else {
        return false;
    };
    let mut request = Vec::with_capacity(filename.len() + 10);
    request.extend_from_slice(&[0, 1]);
    request.extend_from_slice(filename.as_bytes());
    request.push(0);
    request.extend_from_slice(b"octet\0");
    if socket.send_to(&request, server).await.is_err() {
        return false;
    }

    let mut response = [0u8; 516];
    let mut transfer_peer = None;
    let mut expected_block = 1u16;
    let mut offset = 0usize;
    loop {
        let Ok((length, source)) = socket.recv_from(&mut response).await else {
            return false;
        };
        if !source.ip().is_loopback()
            || transfer_peer.is_some_and(|peer| peer != source)
            || length < 4
            || length > response.len()
            || response[..2] != [0, 3]
            || u16::from_be_bytes([response[2], response[3]]) != expected_block
        {
            return false;
        }
        transfer_peer.get_or_insert(source);
        let data = &response[4..length];
        let Some(end) = offset.checked_add(data.len()) else {
            return false;
        };
        let final_block = data.len() < 512;
        if data.len() > 512
            || end > expected.len()
            || data != &expected[offset..end]
            || (final_block && end != expected.len())
        {
            return false;
        }
        if socket
            .send_to(&[0, 4, response[2], response[3]], source)
            .await
            .is_err()
        {
            return false;
        }
        offset = end;
        if final_block {
            return true;
        }
        if offset == expected.len() && expected_block == u16::MAX {
            return false;
        }
        expected_block = expected_block.wrapping_add(1);
    }
}

fn appliance_public_url(public_base_url: &str) -> Option<(Url, Ipv4Addr)> {
    let base = Url::parse(public_base_url).ok()?;
    if base.scheme() != "http"
        || base.port().is_some()
        || base.path() != "/"
        || base.query().is_some()
        || base.fragment().is_some()
    {
        return None;
    }
    let address: Ipv4Addr = base.host_str()?.parse().ok()?;
    Some((base, address))
}

async fn public_boot_url_reachable(public_base_url: &str) -> bool {
    let Some((base, address)) = appliance_public_url(public_base_url) else {
        return false;
    };
    if !is_local_address(IpAddr::V4(address)) {
        return false;
    }
    let Ok(url) = base.join("boot.ipxe?cybex_check=1") else {
        return false;
    };
    let Ok(client) = public_boot_client() else {
        return false;
    };
    let Ok(mut response) = client.get(url).send().await else {
        return false;
    };
    if !response.status().is_success()
        || response
            .content_length()
            .is_some_and(|length| length > MAX_BOOT_CHECK_BYTES as u64)
    {
        return false;
    }
    let mut body = Vec::new();
    loop {
        let Ok(chunk) = response.chunk().await else {
            return false;
        };
        let Some(chunk) = chunk else { break };
        if body.len().saturating_add(chunk.len()) > MAX_BOOT_CHECK_BYTES {
            return false;
        }
        body.extend_from_slice(&chunk);
    }
    body.starts_with(b"#!ipxe\n")
        && body
            .windows(public_base_url.len())
            .any(|window| window == public_base_url.as_bytes())
}

fn public_boot_client() -> Result<Client, reqwest::Error> {
    public_boot_client_builder().build()
}

fn public_boot_client_builder() -> ClientBuilder {
    Client::builder()
        // Connect to the validated appliance LAN address while forcing the
        // source to loopback. nginx consequently forwards 127.0.0.1 and the
        // boot route can authenticate this as its internal checker instead of
        // recording a fake device boot event.
        .local_address(IpAddr::V4(Ipv4Addr::LOCALHOST))
        .redirect(Policy::none())
        .no_proxy()
        .timeout(READINESS_TIMEOUT)
}

fn is_local_address(address: IpAddr) -> bool {
    if address.is_loopback() || address.is_unspecified() || address.is_multicast() {
        return false;
    }
    TcpListener::bind(SocketAddr::new(address, 0)).is_ok()
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener as TokioTcpListener,
        sync::Notify,
    };

    use super::*;

    fn efi_fixture() -> Vec<u8> {
        let mut body = vec![0u8; 32 * 1024];
        body[..2].copy_from_slice(b"MZ");
        body[0x3c..0x40].copy_from_slice(&(0x80u32).to_le_bytes());
        body[0x80..0x84].copy_from_slice(b"PE\0\0");
        body[0x84..0x86].copy_from_slice(&(0x8664u16).to_le_bytes());
        body[0x98..0x9a].copy_from_slice(&(0x20bu16).to_le_bytes());
        body[0xdc..0xde].copy_from_slice(&(10u16).to_le_bytes());
        body
    }

    async fn serve_tftp(socket: UdpSocket, body: Vec<u8>, corrupt_block: Option<u16>) -> usize {
        let mut request = [0u8; 256];
        let (_, peer) = socket.recv_from(&mut request).await.unwrap();
        let mut block = 1u16;
        let mut offset = 0usize;
        loop {
            let end = (offset + 512).min(body.len());
            let mut response = vec![0, 3, (block >> 8) as u8, block as u8];
            response.extend_from_slice(&body[offset..end]);
            if corrupt_block == Some(block) {
                response[4] ^= 0xff;
                socket.send_to(&response, peer).await.unwrap();
                return block as usize;
            }
            socket.send_to(&response, peer).await.unwrap();
            let mut ack = [0u8; 4];
            let (length, source) = socket.recv_from(&mut ack).await.unwrap();
            assert_eq!(source, peer);
            assert_eq!(length, 4);
            assert_eq!(ack, [0, 4, (block >> 8) as u8, block as u8]);
            if end - offset < 512 {
                return block as usize;
            }
            offset = end;
            block += 1;
        }
    }

    #[test]
    fn efi_validation_requires_x86_64_application_shape() {
        let valid = efi_fixture();
        assert!(validate_x86_64_efi_application(&valid));
        let mut wrong_machine = valid.clone();
        wrong_machine[0x84..0x86].copy_from_slice(&(0xaa64u16).to_le_bytes());
        assert!(!validate_x86_64_efi_application(&wrong_machine));
        let mut wrong_subsystem = valid;
        wrong_subsystem[0xdc..0xde].copy_from_slice(&(3u16).to_le_bytes());
        assert!(!validate_x86_64_efi_application(&wrong_subsystem));
        assert!(!validate_x86_64_efi_application(b"MZ"));
    }

    #[test]
    fn ipxe_chain_script_uses_the_dhcp_james_and_normalized_mac_path() {
        let script = std::str::from_utf8(IPXE_AUTOEXEC_BODY).unwrap();
        assert!(script.starts_with("#!ipxe\n"));
        assert!(script.ends_with('\n'));
        assert_eq!(script.matches("dhcp net0 ||").count(), 2);
        assert_eq!(
            script
                .matches("chain --autofree http://${next-server}/boot/${net0/mac:hexhyp}")
                .count(),
            2
        );
        assert!(script.contains("isset ${next-server}"));
        assert!(script.contains("isset ${net0/mac}"));
        assert!(!script.contains("organization"));
        assert!(!script.contains("token"));
    }

    #[test]
    fn staged_ipxe_chain_script_requires_exact_root_owned_shape_and_bytes() {
        let root = std::env::temp_dir().join(format!(
            "cybex-james-readiness-ipxe-script-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
        let asset = root.join(IPXE_AUTOEXEC_FILENAME);
        std::fs::write(&asset, IPXE_AUTOEXEC_BODY).unwrap();
        std::fs::set_permissions(&asset, std::fs::Permissions::from_mode(0o644)).unwrap();
        let owner = std::fs::metadata(&root).unwrap();

        assert_eq!(
            read_safe_public_tftp_ipxe_chain_script(&root, owner.uid(), owner.gid()).as_deref(),
            Some(IPXE_AUTOEXEC_BODY)
        );
        std::fs::write(&asset, b"#!ipxe\nchain http://wrong.example/\n").unwrap();
        assert!(read_safe_public_tftp_ipxe_chain_script(&root, owner.uid(), owner.gid()).is_none());
        std::fs::write(&asset, IPXE_AUTOEXEC_BODY).unwrap();
        std::fs::set_permissions(&asset, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(read_safe_public_tftp_ipxe_chain_script(&root, owner.uid(), owner.gid()).is_none());

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn staged_tftp_asset_requires_public_readability_and_root_only_mutation_shape() {
        let root = std::env::temp_dir().join(format!(
            "cybex-james-readiness-tftp-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
        let asset = root.join("snponly.efi");
        std::fs::write(&asset, efi_fixture()).unwrap();
        std::fs::set_permissions(&asset, std::fs::Permissions::from_mode(0o644)).unwrap();
        let owner = std::fs::metadata(&root).unwrap();

        assert!(
            read_safe_public_tftp_bootloader(&root, "snponly.efi", owner.uid(), owner.gid())
                .is_some()
        );
        std::fs::set_permissions(&asset, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(
            read_safe_public_tftp_bootloader(&root, "snponly.efi", owner.uid(), owner.gid())
                .is_none(),
            "tftpd-hpa rejects a launcher that is not publicly readable"
        );
        std::fs::set_permissions(&asset, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o775)).unwrap();
        assert!(
            read_safe_public_tftp_bootloader(&root, "snponly.efi", owner.uid(), owner.gid())
                .is_none(),
            "the public TFTP tree must never be writable by a service group"
        );

        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn tftp_probe_consumes_and_acks_the_entire_exact_file() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let expected = efi_fixture();
        let task = tokio::spawn(serve_tftp(server, expected.clone(), None));
        assert!(tftp_serves_expected_bootloader(address, "snponly.efi", &expected).await);
        assert_eq!(task.await.unwrap(), expected.len() / 512 + 1);
    }

    #[tokio::test]
    async fn tftp_probe_accepts_and_verifies_the_small_ipxe_chain_script() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let expected = IPXE_AUTOEXEC_BODY.to_vec();
        let task = tokio::spawn(serve_tftp(server, expected.clone(), None));
        assert!(tftp_serves_expected_bootloader(address, IPXE_AUTOEXEC_FILENAME, &expected).await);
        assert_eq!(task.await.unwrap(), expected.len() / 512 + 1);
    }

    #[tokio::test]
    async fn tftp_probe_rejects_corruption_after_the_first_block() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let expected = efi_fixture();
        let task = tokio::spawn(serve_tftp(server, expected.clone(), Some(2)));
        assert!(!tftp_serves_expected_bootloader(address, "snponly.efi", &expected).await);
        task.await.unwrap();
    }

    #[test]
    fn appliance_url_is_an_unambiguous_ipv4_origin() {
        assert!(appliance_public_url("http://192.0.2.20").is_some());
        for invalid in [
            "https://192.0.2.20",
            "http://james.example",
            "http://192.0.2.20:8080",
            "http://192.0.2.20/path",
        ] {
            assert!(appliance_public_url(invalid).is_none(), "{invalid}");
        }
    }

    #[tokio::test]
    async fn public_boot_probe_reaches_a_local_lan_listener_from_loopback() {
        let route = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        route.connect("192.0.2.1:9").unwrap();
        let IpAddr::V4(address) = route.local_addr().unwrap().ip() else {
            panic!("the readiness probe requires an IPv4 appliance interface");
        };
        assert!(!address.is_loopback() && !address.is_unspecified());
        let listener = TokioTcpListener::bind((address, 0)).await.unwrap();
        let destination = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, peer) = listener.accept().await.unwrap();
            assert_eq!(peer.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
            let mut request = [0u8; 1024];
            assert!(stream.read(&mut request).await.unwrap() > 0);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
        });

        let response = public_boot_client()
            .unwrap()
            .get(format!("http://{destination}/boot.ipxe?cybex_check=1"))
            .send()
            .await
            .unwrap();

        assert!(response.status().is_success());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn concurrent_initial_callers_share_the_real_probe_result() {
        let cache = Arc::new(ReadinessCache::default());
        let started = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let launches = Arc::new(AtomicUsize::new(0));
        let key = ReadinessKey {
            public_base_url: "http://192.0.2.20".to_string(),
            bootloader_filename: "snponly.efi".to_string(),
        };
        let leader = {
            let cache = cache.clone();
            let started = started.clone();
            let release = release.clone();
            let launches = launches.clone();
            let key = key.clone();
            tokio::spawn(async move {
                cache
                    .get_or_probe(key, || async move {
                        launches.fetch_add(1, Ordering::SeqCst);
                        started.notify_one();
                        release.notified().await;
                        ApplianceReadiness::standalone()
                    })
                    .await
            })
        };
        started.notified().await;
        let mut followers = Vec::new();
        for _ in 0..32 {
            let cache = cache.clone();
            let key = key.clone();
            followers.push(tokio::spawn(async move {
                cache
                    .get_or_probe(key, || async { panic!("follower launched a probe") })
                    .await
            }));
        }
        timeout(Duration::from_secs(1), async {
            // The leader also holds a receiver until it returns.
            while cache.completion.receiver_count() < followers.len() + 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("followers did not join the initial readiness probe");
        release.notify_one();
        for follower in followers {
            assert!(follower.await.unwrap().ready);
        }
        assert_eq!(launches.load(Ordering::SeqCst), 1);
        assert!(leader.await.unwrap().ready);
        assert!(
            cache
                .get_or_probe(key, || async { panic!("fresh cache launched a probe") })
                .await
                .ready
        );
    }

    #[tokio::test]
    async fn concurrent_refresh_uses_only_bounded_same_key_positive_evidence() {
        let cache = Arc::new(ReadinessCache::default());
        let started = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let key = ReadinessKey {
            public_base_url: "http://192.0.2.20".to_string(),
            bootloader_filename: "snponly.efi".to_string(),
        };
        cache.state.lock().unwrap().result = Some(CachedReadiness {
            probe_id: 1,
            key: key.clone(),
            checked_at: Instant::now() - READINESS_POSITIVE_CACHE_TTL - Duration::from_millis(1),
            result: ApplianceReadiness::standalone(),
        });

        let leader = {
            let cache = cache.clone();
            let started = started.clone();
            let release = release.clone();
            let key = key.clone();
            tokio::spawn(async move {
                cache
                    .get_or_probe(key, || async move {
                        started.notify_one();
                        release.notified().await;
                        ApplianceReadiness::unavailable()
                    })
                    .await
            })
        };
        started.notified().await;

        let stale = cache
            .get_or_probe(key, || async {
                panic!("stale follower launched a second probe")
            })
            .await;
        assert!(stale.ready);
        release.notify_one();
        assert!(!leader.await.unwrap().ready);
    }

    #[tokio::test]
    async fn negative_startup_result_is_retried_without_positive_ttl_delay() {
        let cache = ReadinessCache::default();
        let launches = AtomicUsize::new(0);
        let key = ReadinessKey {
            public_base_url: "http://192.0.2.20".to_string(),
            bootloader_filename: "snponly.efi".to_string(),
        };

        let first = cache
            .get_or_probe(key.clone(), || async {
                launches.fetch_add(1, Ordering::SeqCst);
                ApplianceReadiness::unavailable()
            })
            .await;
        assert!(!first.ready);
        cache
            .state
            .lock()
            .unwrap()
            .result
            .as_mut()
            .unwrap()
            .checked_at = Instant::now() - READINESS_NEGATIVE_CACHE_TTL - Duration::from_millis(1);

        let recovered = cache
            .get_or_probe(key, || async {
                launches.fetch_add(1, Ordering::SeqCst);
                ApplianceReadiness::standalone()
            })
            .await;
        assert!(recovered.ready);
        assert_eq!(launches.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn only_package_owned_bootloader_names_are_supported() {
        assert_eq!(
            package_bootloader_path("snponly.efi"),
            Some(Path::new("/usr/lib/ipxe/snponly.efi"))
        );
        assert_eq!(
            package_bootloader_path("ipxe.efi"),
            Some(Path::new("/usr/lib/ipxe/ipxe-amd64.efi"))
        );
        assert!(package_bootloader_path("custom.efi").is_none());
    }
}
