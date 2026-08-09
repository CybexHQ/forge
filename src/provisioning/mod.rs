//! Provisioned Ubuntu appliance bootstrap.
//!
//! The live ISO uses a media-derived key only until the approved state
//! partition contains a random device key. Every later event is signed by
//! that installed identity.

mod inventory;
mod packages;
mod protocol;
mod storage;

use anyhow::{Context, Result, bail};
use chrono::Utc;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub use inventory::{PulseProvisioningDisk, PulseProvisioningInventory};
pub use protocol::{ProvisioningEnvelope, SignedInstallPlan};

pub const PRODUCTION_MANAGE_ORIGIN: &str = "https://manage.cybex.net";
pub const REQUIRED_MANAGE_ORIGIN: &str = match option_env!("CYBEX_PULSE_BUILD_MANAGE_ORIGIN") {
    Some(origin) => origin,
    None => PRODUCTION_MANAGE_ORIGIN,
};
pub const DEFAULT_ENVELOPE_PATH: &str = "/cdrom/CYBEX_PROVISIONING.BIN";
pub const DEFAULT_PROVISIONING_KEYS_PATH: &str = "/cdrom/cybex/provisioning-public-keys";
pub const DEFAULT_RELEASE_PUBLIC_KEY_PATH: &str = packages::RELEASE_PUBLIC_KEY_PATH;
pub const DEFAULT_AUTOINSTALL_PATH: &str = "/autoinstall.yaml";
pub const DEFAULT_STATE_MOUNT: &str = "/run/cybex-state";

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

    let signed_plan = loop {
        if let Some(plan) = session.plan.take() {
            break protocol::verify_install_plan(
                plan,
                &verified.signing_key,
                &verified.envelope,
                &inventory,
            )?;
        }
        match session.state.as_str() {
            "created" | "awaiting_approval" => {}
            "revoked" | "expired" | "failed" => {
                bail!("this provisioned Pulse media can no longer install")
            }
            state => bail!("provisioning session entered unsupported state {state}"),
        }
        tokio::time::sleep(std::time::Duration::from_secs(
            session.poll_after_seconds.clamp(2, 30).into(),
        ))
        .await;
        session = client.poll_plan(&provisioning_key).await?;
    };

    let fresh_inventory = inventory::collect_inventory().await?;
    inventory::revalidate_plan_hardware(&signed_plan, &fresh_inventory)?;
    let package_delivery = packages::validate_plan_delivery(&signed_plan, media_layout)?;
    inventory::preflight_network(
        &signed_plan,
        &fresh_inventory,
        &verified.envelope.manage_origin,
    )
    .await?;

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
    if package_delivery == packages::PackageDelivery::NetworkSnapshot {
        packages::stage_network_snapshot(&signed_plan, &options.release_public_key_path).await?;
    }
    let fresh_inventory = inventory::collect_inventory().await?;
    inventory::revalidate_plan_hardware(&signed_plan, &fresh_inventory)?;
    inventory::preflight_network(
        &signed_plan,
        &fresh_inventory,
        &verified.envelope.manage_origin,
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
        schema: "cybex.pulse.provisioning-state.v1".to_string(),
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
    storage::materialize_target(&options.target, &options.state_mount, &state)
        .context("materialize installed Pulse appliance")?;
    state.installation_complete = true;
    storage::save_durable_state(&options.state_mount, &state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_origin_is_fixed_https() {
        assert_eq!(PRODUCTION_MANAGE_ORIGIN, "https://manage.cybex.net");
    }
}
