//! Provisioned Ubuntu appliance bootstrap.
//!
//! The live ISO uses a media-derived key only until the approved state
//! partition contains a random device key. Every later event is signed by
//! that installed identity.

mod inventory;
mod network_runtime;
mod packages;
mod protocol;
mod storage;

use anyhow::{Context, Result, bail};
use chrono::Utc;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};
use tracing::warn;

pub use inventory::{JamesProvisioningDisk, JamesProvisioningInventory};
pub use network_runtime::{
    NetworkRuntimeOptions, NetworkRuntimeOutcome, network_fallback_active,
    reconcile_network_runtime,
};
pub use protocol::{ProvisioningEnvelope, SignedInstallPlan};

pub const PRODUCTION_MANAGE_ORIGIN: &str = "https://manage.cybex.net";
pub const REQUIRED_MANAGE_ORIGIN: &str = match option_env!("CYBEX_JAMES_BUILD_MANAGE_ORIGIN") {
    Some(origin) => origin,
    None => PRODUCTION_MANAGE_ORIGIN,
};
pub const DEFAULT_ENVELOPE_PATH: &str = "/cdrom/CYBEX_PROVISIONING.BIN";
pub const DEFAULT_PROVISIONING_KEYS_PATH: &str = "/cdrom/cybex/provisioning-public-keys";
pub const DEFAULT_RELEASE_PUBLIC_KEY_PATH: &str = packages::RELEASE_PUBLIC_KEY_PATH;
pub const DEFAULT_AUTOINSTALL_PATH: &str = "/autoinstall.yaml";
pub const DEFAULT_STATE_MOUNT: &str = "/run/cybex-state";
pub const INSTALLED_PROVISIONING_KEYS_PATH: &str =
    "/usr/share/cybex-james/provisioning-public-keys";

#[derive(Clone, Debug)]
pub struct PrepareOptions {
    pub envelope_path: PathBuf,
    pub provisioning_keys_path: PathBuf,
    pub release_public_key_path: PathBuf,
    pub autoinstall_path: PathBuf,
    pub state_mount: PathBuf,
    pub required_manage_origin: String,
}

impl Default for PrepareOptions {
    fn default() -> Self {
        Self {
            envelope_path: PathBuf::from(DEFAULT_ENVELOPE_PATH),
            provisioning_keys_path: PathBuf::from(DEFAULT_PROVISIONING_KEYS_PATH),
            release_public_key_path: PathBuf::from(DEFAULT_RELEASE_PUBLIC_KEY_PATH),
            autoinstall_path: PathBuf::from(DEFAULT_AUTOINSTALL_PATH),
            state_mount: PathBuf::from(DEFAULT_STATE_MOUNT),
            required_manage_origin: REQUIRED_MANAGE_ORIGIN.to_string(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct FinalizeOptions {
    pub target: PathBuf,
    pub state_mount: PathBuf,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DurableProvisioningState {
    pub schema: String,
    pub session_id: uuid::Uuid,
    pub plan: SignedInstallPlan,
    pub manage_origin: String,
    #[serde(default)]
    pub management_signing_public_key_b64: String,
    pub device_private_key_b64: String,
    pub device_public_key_b64: String,
    pub device_public_key_fingerprint: String,
    pub next_event_sequence: i64,
    pub identity_active: bool,
    pub installation_complete: bool,
    pub updated_at: chrono::DateTime<Utc>,
}

impl DurableProvisioningState {
    pub(crate) fn path(state_mount: &Path) -> PathBuf {
        state_mount.join("provisioning-state.json")
    }

    pub(crate) fn signing_key(&self) -> Result<SigningKey> {
        protocol::signing_key_from_standard_base64(&self.device_private_key_b64)
    }
}

/// Establish authenticity when migrating a dev.3 flat state filesystem into
/// the protected layout. The package carries the governed provisioning keys,
/// while immutable root-snapshot configuration binds organization, origin,
/// device identity and SSH trust. Derived control files must match the signed
/// plan exactly, preventing a self-consistent attacker key/plan replacement.
pub fn validate_legacy_state_promotion(
    state_mount: &Path,
    config_path: &Path,
    provisioning_keys_path: &Path,
) -> Result<()> {
    let control = Path::new("/var/lib/cybex-james/control");
    let agent = if Path::new("/etc/cybex-james/legacy-state-layout").is_file() {
        state_mount.to_path_buf()
    } else {
        state_mount.join("agent")
    };
    let durable_body = read_bounded_nofollow(
        &control.join("provisioning-state.json"),
        512 * 1024,
        "promoted provisioning state",
    )?;
    let durable: DurableProvisioningState =
        serde_json::from_slice(&durable_body).context("parse promoted provisioning state")?;
    if durable.schema != "cybex.james.provisioning-state.v1"
        || !durable.identity_active
        || !durable.installation_complete
        || durable.session_id != durable.plan.session_id
        || durable.manage_origin != REQUIRED_MANAGE_ORIGIN
    {
        bail!("promoted provisioning state invariants are invalid")
    }

    let keys = protocol::load_trusted_provisioning_keys(provisioning_keys_path)?;
    let plan_value = serde_json::to_value(&durable.plan)?;
    let (plan, signer) = protocol::verify_promoted_install_plan(plan_value.clone(), &keys)?;
    if durable.management_signing_public_key_b64 != protocol::standard_base64(signer.to_bytes()) {
        bail!("promoted Management signing key is not the package-trusted plan signer")
    }
    let installed_plan: serde_json::Value = serde_json::from_slice(&read_bounded_nofollow(
        &control.join("install-plan.json"),
        1024 * 1024,
        "promoted install plan",
    )?)?;
    if installed_plan != plan_value {
        bail!("promoted install plan does not match the authenticated durable plan")
    }

    let config = crate::config::AppConfig::load(&config_path.to_path_buf())?;
    let organization_slug_matches = match plan.organization_slug.as_deref() {
        Some(organization_slug) => config.manage.organization_slug == organization_slug,
        None => config.manage.organization_slug.is_empty(),
    };
    if !config.manage.enabled
        || config.manage.api_url != durable.manage_origin
        || config.manage.organization_id != plan.organization_id.to_string()
        || !organization_slug_matches
    {
        bail!("promoted state does not match immutable Management configuration")
    }
    let principal = read_bounded_nofollow(
        Path::new("/etc/ssh/cybex-james-principals"),
        1024,
        "installed James SSH principal",
    )?;
    if principal != format!("{}\n", plan.reserved_device_id).as_bytes() {
        bail!("promoted state does not match the immutable appliance device identity")
    }
    let ssh_ca = read_bounded_nofollow(
        Path::new("/etc/ssh/cybex-james-ca.pub"),
        4096,
        "installed James SSH CA trust",
    )?;
    if ssh_ca != format!("{}\n", plan.ssh_ca_public_keys.join("\n")).as_bytes() {
        bail!("promoted state does not match immutable SSH CA trust")
    }

    let managed: serde_json::Value = serde_json::from_slice(&read_bounded_nofollow(
        &agent.join("manage-state.json"),
        2 * 1024 * 1024,
        "promoted James agent identity",
    )?)?;
    let private = managed
        .get("private_key_b64")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("promoted James agent private key is missing"))?;
    let key = protocol::signing_key_from_standard_base64(private)?;
    let public = protocol::standard_base64(key.verifying_key().to_bytes());
    let fingerprint = protocol::sha256_hex(key.verifying_key().to_bytes());
    if managed.get("device_id").and_then(serde_json::Value::as_str)
        != Some(plan.reserved_device_id.as_str())
        || managed
            .get("public_key_b64")
            .and_then(serde_json::Value::as_str)
            != Some(public.as_str())
        || managed
            .get("public_key_fingerprint")
            .and_then(serde_json::Value::as_str)
            != Some(fingerprint.as_str())
        || durable.device_private_key_b64 != private
        || durable.device_public_key_b64 != public
        || durable.device_public_key_fingerprint != fingerprint
    {
        bail!("promoted James agent identity is inconsistent")
    }

    let approved: serde_json::Value = serde_json::from_slice(&read_bounded_nofollow(
        &control.join("netplan-approved.json"),
        1024 * 1024,
        "promoted approved Netplan",
    )?)?;
    if approved != storage::netplan(&plan.network, &plan) {
        bail!("promoted approved Netplan is not derived from the authenticated plan")
    }
    let fallback_plan = protocol::JamesProvisioningNetworkPlan {
        mode: "dhcp".to_string(),
        interface_id: plan.network.interface_id.clone(),
        address_cidr: None,
        gateway: None,
        dns_servers: Vec::new(),
    };
    let fallback: serde_json::Value = serde_json::from_slice(&read_bounded_nofollow(
        &control.join("netplan-dhcp-fallback.json"),
        1024 * 1024,
        "promoted fallback Netplan",
    )?)?;
    if fallback != storage::netplan(&fallback_plan, &plan) {
        bail!("promoted fallback Netplan is not derived from the authenticated plan")
    }
    let cidrs = read_bounded_nofollow(
        &control.join("management-cidrs.txt"),
        64 * 1024,
        "promoted Management CIDRs",
    )?;
    if cidrs != format!("{}\n", plan.management_cidrs.join("\n")).as_bytes() {
        bail!("promoted Management CIDRs are not derived from the authenticated plan")
    }
    Ok(())
}

fn read_bounded_nofollow(path: &Path, maximum: u64, label: &str) -> Result<Vec<u8>> {
    let before = fs::symlink_metadata(path).with_context(|| format!("inspect {label}"))?;
    if !before.file_type().is_file()
        || before.nlink() != 1
        || before.len() == 0
        || before.len() > maximum
    {
        bail!("{label} is unsafe")
    }
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("open {label}"))?;
    let opened = file.metadata()?;
    if !opened.file_type().is_file()
        || opened.nlink() != 1
        || opened.dev() != before.dev()
        || opened.ino() != before.ino()
        || opened.len() != before.len()
    {
        bail!("{label} changed before it was read")
    }
    let mut body = Vec::with_capacity(usize::try_from(opened.len())?);
    Read::by_ref(&mut file)
        .take(maximum + 1)
        .read_to_end(&mut body)?;
    if body.len() as u64 != opened.len() || body.len() as u64 > maximum {
        bail!("{label} changed while it was read")
    }
    Ok(body)
}

/// Claim the media, wait for approval, create state first, rotate identity,
/// then replace Subiquity's autoinstall document.
pub async fn prepare(options: PrepareOptions) -> Result<()> {
    let media_layout = packages::inspect_media_layout()?;
    let trusted_keys = protocol::load_trusted_provisioning_keys(&options.provisioning_keys_path)?;
    let verified = protocol::load_and_verify_envelope(
        &options.envelope_path,
        &trusted_keys,
        &options.required_manage_origin,
    )?;
    if let Some(probe) =
        storage::existing_state_for_session(&options.state_mount, verified.envelope.session_id)?
    {
        return resume_prepare(&options, &verified, probe, media_layout).await;
    }

    let provisioning_key = protocol::derive_provisioning_key(&verified.envelope.media_secret)?;
    let inventory = inventory::collect_inventory().await?;
    let hardware_digest = inventory::hardware_digest(&inventory)?;
    let client = protocol::ProvisioningClient::new(
        &verified.envelope.manage_origin,
        verified.envelope.session_id,
    )?;
    let mut session = client
        .claim(
            &verified.envelope.media_secret,
            &provisioning_key,
            &inventory,
            &hardware_digest,
        )
        .await?;

    let mut signed_plan = wait_for_approved_plan(
        &client,
        &provisioning_key,
        &verified,
        &inventory,
        &mut session,
        None,
    )
    .await?;
    let (package_delivery, fresh_inventory) = loop {
        match prepare_approved_plan(
            &signed_plan,
            media_layout,
            &options.release_public_key_path,
            &verified.envelope.manage_origin,
        )
        .await
        {
            Ok(prepared) => break prepared,
            Err(failure) => {
                signed_plan = report_failure_and_wait_for_retry(
                    &client,
                    &provisioning_key,
                    &verified,
                    &inventory,
                    &signed_plan,
                    failure,
                )
                .await?;
            }
        }
    };

    // Acknowledgement is deliberately the final pre-write event. Any local
    // hardware, network, media, or package failure before this point can be
    // reported and retried without consuming the monotonic install sequence.
    client
        .send_event(
            &provisioning_key,
            &signed_plan,
            1,
            "plan_acknowledged",
            "succeeded",
            Some(5),
            "Approved install plan validated",
        )
        .await?;
    // This is the server-side point of no return. No target-disk mutation runs
    // before the accepted destructive-stage event.
    client
        .send_event(
            &provisioning_key,
            &signed_plan,
            2,
            "partitioning",
            "started",
            Some(10),
            "Creating plan-bound appliance storage",
        )
        .await?;

    let prepared =
        storage::create_state_partition_first(&signed_plan, &fresh_inventory, &options.state_mount)
            .await?;
    let device_key = SigningKey::generate(&mut OsRng);
    let mut durable = DurableProvisioningState {
        schema: "cybex.james.provisioning-state.v1".to_string(),
        session_id: verified.envelope.session_id,
        plan: signed_plan.clone(),
        manage_origin: verified.envelope.manage_origin.clone(),
        management_signing_public_key_b64: protocol::standard_base64(
            verified.signing_key.to_bytes(),
        ),
        device_private_key_b64: protocol::standard_base64(device_key.to_bytes()),
        device_public_key_b64: protocol::standard_base64(device_key.verifying_key().to_bytes()),
        device_public_key_fingerprint: protocol::sha256_hex(device_key.verifying_key().to_bytes()),
        next_event_sequence: 3,
        identity_active: false,
        installation_complete: false,
        updated_at: Utc::now(),
    };
    storage::save_durable_state(&prepared.state_mount, &durable)?;

    client
        .send_event(
            &provisioning_key,
            &signed_plan,
            3,
            "state_partition_created",
            "succeeded",
            Some(20),
            "Persistent appliance state created",
        )
        .await?;
    durable.next_event_sequence = 4;
    storage::save_durable_state(&prepared.state_mount, &durable)?;
    client
        .send_event(
            &provisioning_key,
            &signed_plan,
            4,
            "identity_persisted",
            "succeeded",
            Some(25),
            "Long-term device identity persisted",
        )
        .await?;
    durable.next_event_sequence = 5;
    storage::save_durable_state(&prepared.state_mount, &durable)?;

    client
        .activate_identity_resilient(&provisioning_key, &device_key, &signed_plan)
        .await?;
    durable.identity_active = true;
    storage::save_durable_state(&prepared.state_mount, &durable)?;

    storage::create_remaining_partitions(&prepared).await?;
    client
        .send_event(
            &device_key,
            &signed_plan,
            5,
            "partitioning",
            "succeeded",
            Some(30),
            "Appliance partition table is ready",
        )
        .await?;
    durable.next_event_sequence = 6;
    storage::save_durable_state(&prepared.state_mount, &durable)?;
    storage::write_autoinstall(
        &options.autoinstall_path,
        &prepared,
        &signed_plan,
        package_delivery,
    )?;
    Ok(())
}

struct PreDestructiveFailure {
    code: &'static str,
    public_message: &'static str,
    source: anyhow::Error,
}

impl PreDestructiveFailure {
    fn new(
        code: &'static str,
        public_message: &'static str,
        source: impl Into<anyhow::Error>,
    ) -> Self {
        Self {
            code,
            public_message,
            source: source.into(),
        }
    }
}

async fn prepare_approved_plan(
    plan: &SignedInstallPlan,
    media_layout: packages::MediaLayout,
    release_public_key_path: &Path,
    manage_origin: &str,
) -> std::result::Result<
    (packages::PackageDelivery, JamesProvisioningInventory),
    PreDestructiveFailure,
> {
    let fresh_inventory = inventory::collect_inventory().await.map_err(|error| {
        PreDestructiveFailure::new(
            "hardware_revalidation_failed",
            "James could not confirm the approved server hardware before disk preparation.",
            error,
        )
    })?;
    inventory::revalidate_plan_hardware(plan, &fresh_inventory).map_err(|error| {
        PreDestructiveFailure::new(
            "hardware_revalidation_failed",
            "James could not confirm the approved server hardware before disk preparation.",
            error,
        )
    })?;
    let package_delivery =
        packages::validate_plan_delivery(plan, media_layout).map_err(|error| {
            PreDestructiveFailure::new(
                "installation_media_validation_failed",
                "James could not validate this installation media against the approved plan.",
                error,
            )
        })?;
    inventory::preflight_network(plan, &fresh_inventory, manage_origin)
        .await
        .map_err(|error| {
            PreDestructiveFailure::new(
                "network_preflight_failed",
                "James could not verify the approved wired network before disk preparation.",
                error,
            )
        })?;
    if package_delivery == packages::PackageDelivery::NetworkSnapshot {
        packages::stage_network_snapshot(plan, release_public_key_path)
            .await
            .map_err(|error| {
                PreDestructiveFailure::new(
                    "package_snapshot_download_failed",
                    "James could not download and verify its approved installation files.",
                    error,
                )
            })?;
    }
    let fresh_inventory = inventory::collect_inventory().await.map_err(|error| {
        PreDestructiveFailure::new(
            "hardware_revalidation_failed",
            "James could not confirm the approved server hardware before disk preparation.",
            error,
        )
    })?;
    inventory::revalidate_plan_hardware(plan, &fresh_inventory).map_err(|error| {
        PreDestructiveFailure::new(
            "hardware_revalidation_failed",
            "James could not confirm the approved server hardware before disk preparation.",
            error,
        )
    })?;
    inventory::preflight_network(plan, &fresh_inventory, manage_origin)
        .await
        .map_err(|error| {
            PreDestructiveFailure::new(
                "network_preflight_failed",
                "James could not verify the approved wired network before disk preparation.",
                error,
            )
        })?;
    Ok((package_delivery, fresh_inventory))
}

async fn report_failure_and_wait_for_retry(
    client: &protocol::ProvisioningClient,
    provisioning_key: &SigningKey,
    verified: &protocol::VerifiedEnvelope,
    inventory: &JamesProvisioningInventory,
    failed_plan: &SignedInstallPlan,
    failure: PreDestructiveFailure,
) -> Result<SignedInstallPlan> {
    warn!(
        failure_code = failure.code,
        error = %failure.source,
        "James setup stopped safely before disk preparation"
    );
    let mut reported = false;
    loop {
        if !reported {
            match client
                .send_event(
                    provisioning_key,
                    failed_plan,
                    1,
                    failure.code,
                    "failed",
                    None,
                    failure.public_message,
                )
                .await
            {
                Ok(()) => reported = true,
                Err(error) => warn!(
                    failure_code = failure.code,
                    error = %error,
                    "could not report the safe James setup failure; retrying"
                ),
            }
        }

        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        let mut next = match client.poll_plan(provisioning_key).await {
            Ok(next) => {
                // A failed state proves that a prior request committed even if
                // its HTTP response was lost. Awaiting approval means an
                // administrator already acknowledged the safe retry.
                if matches!(next.state.as_str(), "failed" | "awaiting_approval") {
                    reported = true;
                }
                next
            }
            Err(error) => {
                warn!(
                    failure_code = failure.code,
                    error = %error,
                    "James is waiting for Management connectivity to recover"
                );
                continue;
            }
        };
        if matches!(next.state.as_str(), "revoked" | "expired") {
            bail!("this provisioned James installation was revoked or expired")
        }
        if next.state == "approved" {
            if let Some(plan) = next.plan.take() {
                let plan = protocol::verify_install_plan(
                    plan,
                    &verified.signing_key,
                    &verified.envelope,
                    inventory,
                )?;
                if plan.id != failed_plan.id {
                    return Ok(plan);
                }
            }
        }
    }
}

async fn wait_for_approved_plan(
    client: &protocol::ProvisioningClient,
    provisioning_key: &SigningKey,
    verified: &protocol::VerifiedEnvelope,
    inventory: &JamesProvisioningInventory,
    session: &mut protocol::AgentSessionResponse,
    previous_plan_id: Option<uuid::Uuid>,
) -> Result<SignedInstallPlan> {
    loop {
        if session.state == "approved" {
            if let Some(plan) = session.plan.take() {
                let plan = protocol::verify_install_plan(
                    plan,
                    &verified.signing_key,
                    &verified.envelope,
                    inventory,
                )?;
                if previous_plan_id != Some(plan.id) {
                    return Ok(plan);
                }
            }
        }
        match session.state.as_str() {
            "created" | "awaiting_approval" | "approved" => {}
            "revoked" | "expired" | "failed" => {
                bail!("this provisioned James media can no longer install")
            }
            state => bail!("provisioning session entered unsupported state {state}"),
        }
        tokio::time::sleep(std::time::Duration::from_secs(
            session.poll_after_seconds.clamp(2, 30).into(),
        ))
        .await;
        *session = client.poll_plan(provisioning_key).await?;
    }
}

async fn resume_prepare(
    options: &PrepareOptions,
    verified: &protocol::VerifiedEnvelope,
    probe: storage::ExistingStateProbe,
    media_layout: packages::MediaLayout,
) -> Result<()> {
    let mut durable = probe.state.clone();
    if durable.manage_origin != verified.envelope.manage_origin
        || durable.management_signing_public_key_b64
            != protocol::standard_base64(verified.signing_key.to_bytes())
        || durable.next_event_sequence < 3
        || durable.next_event_sequence > 6
    {
        bail!("durable appliance recovery state does not match this signed media")
    }
    let inventory = inventory::collect_inventory().await?;
    let signed_plan = protocol::verify_durable_install_plan(
        serde_json::to_value(&durable.plan)?,
        &verified.signing_key,
        &verified.envelope,
        &inventory,
    )?;
    let package_delivery = packages::validate_plan_delivery(&signed_plan, media_layout)?;
    inventory::revalidate_durable_plan_hardware(&signed_plan, &inventory)?;
    inventory::preflight_network(&signed_plan, &inventory, &verified.envelope.manage_origin)
        .await?;
    if package_delivery == packages::PackageDelivery::NetworkSnapshot {
        packages::stage_network_snapshot(&signed_plan, &options.release_public_key_path).await?;
    }
    let inventory = inventory::collect_inventory().await?;
    inventory::revalidate_durable_plan_hardware(&signed_plan, &inventory)?;
    inventory::preflight_network(&signed_plan, &inventory, &verified.envelope.manage_origin)
        .await?;
    let prepared =
        storage::resume_prepared_storage(&signed_plan, &inventory, &options.state_mount).await?;
    durable = storage::activate_existing_state(&options.state_mount, &probe)?;
    let provisioning_key = protocol::derive_provisioning_key(&verified.envelope.media_secret)?;
    let device_key = durable.signing_key()?;
    if durable.device_public_key_b64
        != protocol::standard_base64(device_key.verifying_key().to_bytes())
        || protocol::sha256_hex(device_key.verifying_key().to_bytes())
            != durable.device_public_key_fingerprint
    {
        bail!("durable appliance device identity is inconsistent")
    }
    let client = protocol::ProvisioningClient::new(
        &verified.envelope.manage_origin,
        verified.envelope.session_id,
    )?;
    if durable.next_event_sequence == 3 {
        client
            .send_event(
                &provisioning_key,
                &signed_plan,
                3,
                "state_partition_created",
                "succeeded",
                Some(20),
                "Persistent appliance state recovered",
            )
            .await?;
        durable.next_event_sequence = 4;
        storage::save_durable_state(&prepared.state_mount, &durable)?;
    }
    if durable.next_event_sequence == 4 {
        client
            .send_event(
                &provisioning_key,
                &signed_plan,
                4,
                "identity_persisted",
                "succeeded",
                Some(25),
                "Long-term device identity recovered",
            )
            .await?;
        durable.next_event_sequence = 5;
        storage::save_durable_state(&prepared.state_mount, &durable)?;
    }
    if !durable.identity_active {
        client
            .activate_identity_resilient(&provisioning_key, &device_key, &signed_plan)
            .await?;
        durable.identity_active = true;
        storage::save_durable_state(&prepared.state_mount, &durable)?;
    }
    storage::create_remaining_partitions(&prepared).await?;
    if durable.next_event_sequence == 5 {
        client
            .send_event(
                &device_key,
                &signed_plan,
                5,
                "partitioning",
                "succeeded",
                Some(30),
                "Appliance partition table recovered",
            )
            .await?;
        durable.next_event_sequence = 6;
        storage::save_durable_state(&prepared.state_mount, &durable)?;
    }
    storage::write_autoinstall(
        &options.autoinstall_path,
        &prepared,
        &signed_plan,
        package_delivery,
    )
}

/// Send one late-install event using the device key on CYBEX_STATE.
pub async fn report_install_stage(
    state_mount: &Path,
    stage: &str,
    status: &str,
    progress_percent: Option<i32>,
    message: &str,
) -> Result<()> {
    let mut state = storage::load_durable_state(state_mount)?;
    if !state.identity_active {
        bail!("installed device identity is not active")
    }
    let signing_key = state.signing_key()?;
    let client = protocol::ProvisioningClient::new(&state.manage_origin, state.session_id)?;
    client
        .send_event(
            &signing_key,
            &state.plan,
            state.next_event_sequence,
            stage,
            status,
            progress_percent,
            message,
        )
        .await?;
    state.next_event_sequence += 1;
    storage::save_durable_state(state_mount, &state)
}

/// Materialize plan-bound config into the newly installed target.
pub fn finalize_target(options: FinalizeOptions) -> Result<()> {
    let mut state = storage::load_durable_state(&options.state_mount)?;
    if !state.identity_active {
        bail!("cannot finalize an appliance before identity activation")
    }
    state.installation_complete = true;
    storage::materialize_target(&options.target, &options.state_mount, &state)
        .context("materialize installed James appliance")?;
    storage::save_durable_state(&options.state_mount, &state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_origin_is_fixed_https() {
        assert_eq!(PRODUCTION_MANAGE_ORIGIN, "https://manage.cybex.net");
    }

    #[test]
    fn pre_destructive_failure_keeps_raw_diagnostics_local() {
        let failure = PreDestructiveFailure::new(
            "network_preflight_failed",
            "James could not verify the approved wired network before disk preparation.",
            anyhow::anyhow!("run arping with secret token should stay local"),
        );
        assert!(
            failure
                .code
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        );
        assert!(failure.public_message.len() <= 512);
        assert!(!failure.public_message.contains("arping"));
        assert!(!failure.public_message.contains("secret"));
        assert!(failure.source.to_string().contains("arping"));
    }

    #[test]
    fn pre_destructive_failure_is_reported_before_plan_acknowledgement() {
        let source = include_str!("mod.rs");
        let prepare = source
            .split_once("pub async fn prepare")
            .expect("prepare entry point")
            .1
            .split_once("struct PreDestructiveFailure")
            .expect("pre-destructive failure boundary")
            .0;
        let preflight = prepare
            .find("prepare_approved_plan(")
            .expect("approved plan preflight");
        let recovery = prepare
            .find("report_failure_and_wait_for_retry(")
            .expect("signed failure recovery");
        let acknowledged = prepare
            .find("\"plan_acknowledged\"")
            .expect("plan acknowledgement");

        assert!(preflight < recovery);
        assert!(recovery < acknowledged);

        let reporting = source
            .split_once("async fn report_failure_and_wait_for_retry")
            .expect("failure reporting helper")
            .1
            .split_once("async fn wait_for_approved_plan")
            .expect("approved-plan polling boundary")
            .0;
        assert!(reporting.contains("\"failed\""));
        assert!(reporting.contains("client.poll_plan(provisioning_key)"));
        assert!(reporting.contains("plan.id != failed_plan.id"));
    }
}
