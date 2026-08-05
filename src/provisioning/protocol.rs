use super::inventory::{
    ForgeProvisioningDisk, ForgeProvisioningEthernetInterface, ForgeProvisioningInventory,
};
use anyhow::{Context, Result, anyhow, bail};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chrono::{DateTime, SecondsFormat, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::{RngCore, rngs::OsRng};
use reqwest::{Method, StatusCode, redirect::Policy};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{fs, path::Path, time::Duration};
use uuid::Uuid;

const ENVELOPE_SIZE: usize = 8192;
const ENVELOPE_SCHEMA: &str = "cybex.forge.provisioning-envelope.v1";
const ENVELOPE_SIGNATURE_DOMAIN: &str = "CYBEX-FORGE-PROVISIONING-ENVELOPE-V1";
const KEY_DERIVATION_DOMAIN: &[u8] = b"CYBEX-FORGE-PROVISIONING-KEY-V1\0";
const REQUEST_SIGNATURE_DOMAIN: &str = "CYBEX-FORGE-PROVISIONING-V1";
const INSTALL_PLAN_SCHEMA: &str = "cybex.forge.install-plan.v1";
const INSTALL_PLAN_SIGNATURE_DOMAIN: &str = "CYBEX-FORGE-INSTALL-PLAN-V1";
const IDENTITY_TRANSITION_SIGNATURE_DOMAIN: &str = "CYBEX-FORGE-IDENTITY-TRANSITION-V1";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvisioningEnvelope {
    pub schema: String,
    pub session_id: Uuid,
    pub media_secret: String,
    pub manage_origin: String,
    pub release_version: String,
    pub template_sha256: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub signature: String,
    pub zero_padding: String,
}

pub(crate) struct VerifiedEnvelope {
    pub envelope: ProvisioningEnvelope,
    pub signing_key: VerifyingKey,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForgeProvisioningNetworkPlan {
    pub mode: String,
    pub interface_id: String,
    pub address_cidr: Option<String>,
    pub gateway: Option<String>,
    #[serde(default)]
    pub dns_servers: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForgeMaintenanceWindowPlan {
    pub timezone: String,
    pub weekday: u8,
    pub start: String,
    pub duration_minutes: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedInstallPlan {
    pub schema: String,
    pub id: Uuid,
    pub organization_id: Uuid,
    pub plan_revision: i64,
    pub session_id: Uuid,
    pub session_revision: i64,
    pub inventory_sha256: String,
    pub provisioning_public_key_fingerprint: String,
    pub reserved_device_id: String,
    pub display_name: String,
    pub target_disk_id: String,
    pub target_disk: ForgeProvisioningDisk,
    pub network_interface: ForgeProvisioningEthernetInterface,
    pub network: ForgeProvisioningNetworkPlan,
    pub maintenance_window: ForgeMaintenanceWindowPlan,
    #[serde(default)]
    pub management_cidrs: Vec<String>,
    #[serde(default)]
    pub ssh_ca_public_keys: Vec<String>,
    pub base_os: String,
    pub base_os_version: String,
    pub release_version: String,
    pub at_rest_protection: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub plan_sha256: String,
    pub signature: String,
}

#[derive(Debug, Serialize)]
struct ClaimRequest<'a> {
    session_id: Uuid,
    provisioning_public_key: String,
    provisioning_public_key_fingerprint: String,
    hardware_digest: &'a str,
    inventory: &'a ForgeProvisioningInventory,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AgentSessionResponse {
    pub session_id: Uuid,
    pub state: String,
    pub session_revision: i64,
    pub poll_after_seconds: u32,
    pub plan: Option<Value>,
}

#[derive(Debug, Serialize)]
struct EventRequest<'a> {
    event_id: Uuid,
    sequence: i64,
    plan_id: Option<Uuid>,
    stage: &'a str,
    status: &'a str,
    progress_percent: Option<i32>,
    message: &'a str,
    payload: Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EventResponse {
    accepted: bool,
    session_state: String,
    session_revision: i64,
}

#[derive(Debug, Serialize)]
struct ActivateIdentityRequest {
    plan_id: Uuid,
    device_id: String,
    long_term_public_key: String,
    long_term_public_key_fingerprint: String,
    transition_signature_by_provisioning_key: String,
    transition_signature_by_device_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivateIdentityResponse {
    device_id: String,
    state: String,
    session_revision: i64,
}

pub(crate) fn load_trusted_provisioning_keys(path: &Path) -> Result<Vec<VerifyingKey>> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("read provisioning trust keys from {}", path.display()))?;
    let mut keys = Vec::new();
    let mut previous = None;
    for line in raw.lines() {
        let value = line.trim();
        if value.is_empty() || value.starts_with('#') {
            continue;
        }
        if previous.is_some_and(|prior: &str| prior >= value) {
            bail!("provisioning trust keys must be sorted and unique")
        }
        let bytes = canonical_standard_base64(value, 32)?;
        let key = VerifyingKey::from_bytes(
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| anyhow!("provisioning public key length is invalid"))?,
        )
        .context("parse provisioning public key")?;
        if key.is_weak() {
            bail!("weak provisioning public key is forbidden")
        }
        keys.push(key);
        previous = Some(value);
    }
    if keys.is_empty() || keys.len() > 8 {
        bail!("the ISO must contain between one and eight provisioning trust keys")
    }
    Ok(keys)
}

pub(crate) fn load_and_verify_envelope(
    path: &Path,
    trusted_keys: &[VerifyingKey],
    required_manage_origin: &str,
) -> Result<VerifiedEnvelope> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    if bytes.len() != ENVELOPE_SIZE {
        bail!("provisioning envelope slot must be exactly 8192 bytes")
    }
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    if bytes[end..].iter().any(|byte| *byte != 0) {
        bail!("provisioning envelope padding is not canonical")
    }
    let body = bytes[..end].strip_suffix(b"\n").unwrap_or(&bytes[..end]);
    let envelope: ProvisioningEnvelope =
        serde_json::from_slice(body).context("parse provisioning envelope")?;
    validate_envelope_fields(&envelope, required_manage_origin)?;
    let signature = canonical_url_base64(&envelope.signature, 64)?;
    let signature = Signature::from_bytes(
        signature
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("provisioning envelope signature length is invalid"))?,
    );
    let unsigned = canonical_json(json!({
        "schema": envelope.schema,
        "session_id": envelope.session_id,
        "media_secret": envelope.media_secret,
        "manage_origin": envelope.manage_origin,
        "release_version": envelope.release_version,
        "template_sha256": envelope.template_sha256,
        "issued_at": envelope.issued_at,
        "expires_at": envelope.expires_at,
    }));
    let canonical = serde_json::to_vec(&unsigned).context("serialize provisioning envelope")?;
    let mut payload = ENVELOPE_SIGNATURE_DOMAIN.as_bytes().to_vec();
    payload.push(b'\n');
    payload.extend_from_slice(&canonical);
    let signing_key = trusted_keys
        .iter()
        .find(|key| key.verify(&payload, &signature).is_ok())
        .copied()
        .ok_or_else(|| anyhow!("provisioning envelope signature is not trusted"))?;
    Ok(VerifiedEnvelope {
        envelope,
        signing_key,
    })
}

fn validate_envelope_fields(
    envelope: &ProvisioningEnvelope,
    required_manage_origin: &str,
) -> Result<()> {
    if envelope.schema != ENVELOPE_SCHEMA || !envelope.zero_padding.is_empty() {
        bail!("provisioning envelope schema is unsupported")
    }
    if envelope.manage_origin != required_manage_origin {
        bail!("provisioning media is not bound to the production Management origin")
    }
    let origin = reqwest::Url::parse(&envelope.manage_origin)
        .context("provisioning Management origin is invalid")?;
    if origin.scheme() != "https"
        || origin.host_str().is_none()
        || origin.path() != "/"
        || origin.query().is_some()
        || origin.fragment().is_some()
        || !origin.username().is_empty()
        || origin.password().is_some()
    {
        bail!("provisioning Management origin is not a canonical HTTPS origin")
    }
    canonical_url_base64(&envelope.media_secret, 32)?;
    require_sha256(&envelope.template_sha256, "template SHA-256")?;
    if envelope.release_version.is_empty() || envelope.release_version.len() > 128 {
        bail!("provisioning release version is invalid")
    }
    let now = Utc::now();
    if envelope.issued_at > now + chrono::Duration::minutes(5)
        || envelope.expires_at <= now
        || envelope.expires_at <= envelope.issued_at
        || envelope.expires_at - envelope.issued_at > chrono::Duration::hours(24)
    {
        bail!("provisioning envelope is expired or has invalid validity")
    }
    Ok(())
}

pub(crate) fn derive_provisioning_key(media_secret: &str) -> Result<SigningKey> {
    let secret = canonical_url_base64(media_secret, 32)?;
    let mut digest = Sha256::new();
    digest.update(KEY_DERIVATION_DOMAIN);
    digest.update(secret);
    Ok(SigningKey::from_bytes(&digest.finalize().into()))
}

pub(crate) fn verify_install_plan(
    value: Value,
    signing_key: &VerifyingKey,
    envelope: &ProvisioningEnvelope,
    inventory_sha256: &str,
) -> Result<SignedInstallPlan> {
    verify_install_plan_inner(value, signing_key, envelope, inventory_sha256, false)
}

pub(crate) fn verify_durable_install_plan(
    value: Value,
    signing_key: &VerifyingKey,
    envelope: &ProvisioningEnvelope,
    inventory_sha256: &str,
) -> Result<SignedInstallPlan> {
    verify_install_plan_inner(value, signing_key, envelope, inventory_sha256, true)
}

fn verify_install_plan_inner(
    value: Value,
    signing_key: &VerifyingKey,
    envelope: &ProvisioningEnvelope,
    inventory_sha256: &str,
    acknowledged_attempt: bool,
) -> Result<SignedInstallPlan> {
    let plan: SignedInstallPlan =
        serde_json::from_value(value.clone()).context("parse signed install plan")?;
    let expected_provisioning_fingerprint = sha256_hex(
        derive_provisioning_key(&envelope.media_secret)?
            .verifying_key()
            .to_bytes(),
    );
    if plan.schema != INSTALL_PLAN_SCHEMA
        || plan.session_id != envelope.session_id
        || plan.organization_id.is_nil()
        || plan.release_version != envelope.release_version
        || plan.inventory_sha256 != inventory_sha256
        || plan.provisioning_public_key_fingerprint != expected_provisioning_fingerprint
        || plan.base_os != "ubuntu"
        || plan.base_os_version != "26.04"
        || plan.at_rest_protection != "none"
        || plan.plan_revision <= 0
        || plan.session_revision <= 0
    {
        bail!("install plan does not match this media and inventory")
    }
    if plan.target_disk_id != plan.target_disk.id
        || plan.network.interface_id != plan.network_interface.id
        || !plan.network_interface.link_up
        || plan.reserved_device_id.len() < 16
        || plan.reserved_device_id.len() > 96
        || !plan.reserved_device_id.starts_with("dev_")
        || !plan
            .reserved_device_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        bail!("install plan contains mismatched device identities")
    }
    if plan.ssh_ca_public_keys.is_empty()
        || plan.ssh_ca_public_keys.len() > 2
        || plan.ssh_ca_public_keys.iter().any(|key| {
            !key.starts_with("ssh-ed25519 ")
                || key.len() > 1024
                || key.chars().any(|character| character.is_control())
        })
    {
        bail!("install plan contains invalid SSH CA trust")
    }
    require_sha256(&plan.plan_sha256, "install plan SHA-256")?;
    if (!acknowledged_attempt && plan.expires_at <= Utc::now())
        || plan.expires_at <= plan.issued_at
        || plan.expires_at - plan.issued_at > chrono::Duration::minutes(30)
    {
        bail!("install plan is expired or has invalid validity")
    }
    let mut unsigned = value;
    let object = unsigned
        .as_object_mut()
        .ok_or_else(|| anyhow!("install plan must be a JSON object"))?;
    object.remove("signature");
    object.remove("plan_sha256");
    let unsigned = canonical_json(unsigned);
    let canonical = serde_json::to_vec(&unsigned).context("serialize signed install plan")?;
    if sha256_hex(&canonical) != plan.plan_sha256 {
        bail!("install plan digest does not match its exact body")
    }
    let signature = canonical_url_base64(&plan.signature, 64)?;
    let signature = Signature::from_bytes(
        signature
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("install plan signature length is invalid"))?,
    );
    let mut payload = INSTALL_PLAN_SIGNATURE_DOMAIN.as_bytes().to_vec();
    payload.push(b'\n');
    payload.extend_from_slice(&canonical);
    signing_key
        .verify(&payload, &signature)
        .context("install plan signature is not trusted")?;
    Ok(plan)
}

pub(crate) struct ProvisioningClient {
    origin: String,
    session_id: Uuid,
    http: reqwest::Client,
}

impl ProvisioningClient {
    pub(crate) fn new(origin: &str, session_id: Uuid) -> Result<Self> {
        let http = reqwest::Client::builder()
            .redirect(Policy::none())
            .timeout(Duration::from_secs(30))
            .https_only(true)
            .user_agent(concat!("cybex-forge-bootstrap/", env!("CARGO_PKG_VERSION")))
            .build()
            .context("build provisioning HTTP client")?;
        Ok(Self {
            origin: origin.trim_end_matches('/').to_string(),
            session_id,
            http,
        })
    }

    pub(crate) async fn claim(
        &self,
        media_secret: &str,
        key: &SigningKey,
        inventory: &ForgeProvisioningInventory,
        hardware_digest: &str,
    ) -> Result<AgentSessionResponse> {
        let public = key.verifying_key().to_bytes();
        let request = ClaimRequest {
            session_id: self.session_id,
            provisioning_public_key: standard_base64(public),
            provisioning_public_key_fingerprint: sha256_hex(public),
            hardware_digest,
            inventory,
        };
        let response = self
            .signed_json(
                Method::POST,
                "/v1/agent/forge/provisioning-sessions/claim",
                key,
                Some(media_secret),
                Some(&request),
            )
            .await?;
        self.validate_session_response(response)
    }

    pub(crate) async fn poll_plan(&self, key: &SigningKey) -> Result<AgentSessionResponse> {
        let path = format!(
            "/v1/agent/forge/provisioning-sessions/{}/plan",
            self.session_id
        );
        let response = self
            .signed_json::<Value, AgentSessionResponse>(Method::GET, &path, key, None, None)
            .await?;
        self.validate_session_response(response)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn send_event(
        &self,
        key: &SigningKey,
        plan: &SignedInstallPlan,
        sequence: i64,
        stage: &str,
        status: &str,
        progress_percent: Option<i32>,
        message: &str,
    ) -> Result<()> {
        if sequence <= 0
            || !stage
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
            || !matches!(status, "pending" | "started" | "succeeded" | "failed")
            || message.len() > 512
        {
            bail!("invalid provisioning progress event")
        }
        let request = EventRequest {
            event_id: deterministic_event_id(self.session_id, plan.id, sequence),
            sequence,
            plan_id: Some(plan.id),
            stage,
            status,
            progress_percent,
            message,
            payload: json!({}),
        };
        let path = format!(
            "/v1/agent/forge/provisioning-sessions/{}/events",
            self.session_id
        );
        let response: EventResponse = self
            .signed_json(Method::POST, &path, key, None, Some(&request))
            .await?;
        let _ = (
            response.accepted,
            response.session_state,
            response.session_revision,
        );
        Ok(())
    }

    pub(crate) async fn activate_identity_resilient(
        &self,
        provisioning_key: &SigningKey,
        device_key: &SigningKey,
        plan: &SignedInstallPlan,
    ) -> Result<()> {
        let provisioning_fingerprint = sha256_hex(provisioning_key.verifying_key().to_bytes());
        let device_public = device_key.verifying_key().to_bytes();
        let device_fingerprint = sha256_hex(device_public);
        let transition = format!(
            "{IDENTITY_TRANSITION_SIGNATURE_DOMAIN}\n{}\n{}\n{}\n{}\n{}\n",
            self.session_id,
            plan.id,
            plan.reserved_device_id,
            provisioning_fingerprint,
            device_fingerprint,
        );
        let request = ActivateIdentityRequest {
            plan_id: plan.id,
            device_id: plan.reserved_device_id.clone(),
            long_term_public_key: standard_base64(device_public),
            long_term_public_key_fingerprint: device_fingerprint,
            transition_signature_by_provisioning_key: URL_SAFE_NO_PAD
                .encode(provisioning_key.sign(transition.as_bytes()).to_bytes()),
            transition_signature_by_device_key: URL_SAFE_NO_PAD
                .encode(device_key.sign(transition.as_bytes()).to_bytes()),
        };
        let path = format!(
            "/v1/agent/forge/provisioning-sessions/{}/activate-identity",
            self.session_id
        );
        let first = self
            .signed_json::<_, ActivateIdentityResponse>(
                Method::POST,
                &path,
                provisioning_key,
                None,
                Some(&request),
            )
            .await;
        let response = match first {
            Ok(response) => response,
            Err(first_error) => self
                .signed_json::<_, ActivateIdentityResponse>(
                    Method::POST,
                    &path,
                    device_key,
                    None,
                    Some(&request),
                )
                .await
                .with_context(|| {
                    format!(
                        "identity activation failed before and after key transition: {first_error}"
                    )
                })?,
        };
        if response.device_id != plan.reserved_device_id {
            bail!("identity activation returned a different device")
        }
        let _ = (response.state, response.session_revision);
        Ok(())
    }

    async fn signed_json<B: Serialize + ?Sized, R: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        key: &SigningKey,
        media_secret: Option<&str>,
        body: Option<&B>,
    ) -> Result<R> {
        let body = match body {
            Some(body) => serde_json::to_vec(body).context("serialize provisioning request")?,
            None => Vec::new(),
        };
        let timestamp = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
        let request_id = random_request_id();
        let canonical = format!(
            "{REQUEST_SIGNATURE_DOMAIN}\n{}\n{}\n{}\n{}\n{}",
            method.as_str().to_uppercase(),
            path,
            timestamp,
            request_id,
            sha256_hex(&body),
        );
        let signature = URL_SAFE_NO_PAD.encode(key.sign(canonical.as_bytes()).to_bytes());
        let mut request = self
            .http
            .request(method, format!("{}{}", self.origin, path))
            .header("x-cybex-request-id", request_id)
            .header("x-cybex-timestamp", timestamp)
            .header("x-cybex-signature", signature);
        if let Some(secret) = media_secret {
            request = request.header("x-cybex-forge-provisioning-secret", secret);
        }
        if !body.is_empty() {
            request = request
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body);
        }
        let response = request.send().await.context("send provisioning request")?;
        let status = response.status();
        let bytes = response
            .bytes()
            .await
            .context("read provisioning response")?;
        if bytes.len() > 1024 * 1024 {
            bail!("provisioning response exceeds its size limit")
        }
        if !status.is_success() {
            return Err(safe_http_error(status, &bytes));
        }
        serde_json::from_slice(&bytes).context("parse provisioning response")
    }

    fn validate_session_response(
        &self,
        response: AgentSessionResponse,
    ) -> Result<AgentSessionResponse> {
        if response.session_id != self.session_id || response.session_revision <= 0 {
            bail!("Management returned a mismatched provisioning session")
        }
        Ok(response)
    }
}

fn safe_http_error(status: StatusCode, body: &[u8]) -> anyhow::Error {
    let value: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
    let code = value
        .get("code")
        .and_then(Value::as_str)
        .filter(|value| value.len() <= 64)
        .unwrap_or("request_rejected");
    anyhow!("Management rejected provisioning request ({status}, {code})")
}

fn deterministic_event_id(session_id: Uuid, plan_id: Uuid, sequence: i64) -> Uuid {
    let mut digest = Sha256::new();
    digest.update(b"CYBEX-FORGE-PROVISIONING-EVENT-ID-V1\0");
    digest.update(session_id.as_bytes());
    digest.update(plan_id.as_bytes());
    digest.update(sequence.to_be_bytes());
    let digest = digest.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn random_request_id() -> String {
    let mut bytes = [0_u8; 16];
    OsRng.fill_bytes(&mut bytes);
    format!("req_{}", hex::encode(bytes))
}

pub(crate) fn sha256_hex(bytes: impl AsRef<[u8]>) -> String {
    hex::encode(Sha256::digest(bytes.as_ref()))
}

pub(crate) fn standard_base64(bytes: impl AsRef<[u8]>) -> String {
    STANDARD.encode(bytes.as_ref())
}

pub(crate) fn signing_key_from_standard_base64(value: &str) -> Result<SigningKey> {
    let bytes = canonical_standard_base64(value, 32)?;
    Ok(SigningKey::from_bytes(
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("device private key length is invalid"))?,
    ))
}

fn canonical_standard_base64(value: &str, expected: usize) -> Result<Vec<u8>> {
    if value.is_empty() || value.trim() != value || value.chars().any(char::is_whitespace) {
        bail!("value is not canonical standard Base64")
    }
    let bytes = STANDARD.decode(value).context("decode standard Base64")?;
    if bytes.len() != expected || STANDARD.encode(&bytes) != value {
        bail!("value is not canonical standard Base64")
    }
    Ok(bytes)
}

fn canonical_url_base64(value: &str, expected: usize) -> Result<Vec<u8>> {
    if value.is_empty() || value.trim() != value || value.chars().any(char::is_whitespace) {
        bail!("value is not canonical URL-safe Base64")
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .context("decode URL-safe Base64")?;
    if bytes.len() != expected || URL_SAFE_NO_PAD.encode(&bytes) != value {
        bail!("value is not canonical URL-safe Base64")
    }
    Ok(bytes)
}

fn require_sha256(value: &str, label: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{label} is invalid")
    }
    Ok(())
}

fn canonical_json(value: Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut keys = object.keys().cloned().collect::<Vec<_>>();
            keys.sort();
            let mut canonical = serde_json::Map::new();
            for key in keys {
                canonical.insert(key.clone(), canonical_json(object[&key].clone()));
            }
            Value::Object(canonical)
        }
        Value::Array(values) => Value::Array(values.into_iter().map(canonical_json).collect()),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derived_media_key_is_domain_separated_and_stable() {
        let secret = URL_SAFE_NO_PAD.encode([9_u8; 32]);
        let first = derive_provisioning_key(&secret).unwrap();
        let second = derive_provisioning_key(&secret).unwrap();
        assert_eq!(first.to_bytes(), second.to_bytes());
        assert_ne!(first.to_bytes(), [9_u8; 32]);
    }

    #[test]
    fn event_ids_are_stable_and_sequence_bound() {
        let session = Uuid::from_bytes([1_u8; 16]);
        let plan = Uuid::from_bytes([2_u8; 16]);
        assert_eq!(
            deterministic_event_id(session, plan, 7),
            deterministic_event_id(session, plan, 7)
        );
        assert_ne!(
            deterministic_event_id(session, plan, 7),
            deterministic_event_id(session, plan, 8)
        );
    }
}
