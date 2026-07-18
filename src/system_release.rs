use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, bail};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chrono::{DateTime, SecondsFormat, Utc};
use ed25519_dalek::{Signer, SigningKey};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::config::AppConfig;
use crate::system_release_compiler_v3;

pub const SYSTEM_RELEASE_BUILD_SPEC_SCHEMA_VERSION: u32 = 3;
pub const SYSTEM_RELEASE_FORGE_PROTOCOL: u32 = 5;
pub const SYSTEM_RELEASE_BUILD_KIND: &str = "system_release_nixos_configuration";
pub const SYSTEM_RELEASE_BUILD_TARGET: &str = "system_release";
pub const SYSTEM_RELEASE_ARTIFACT_TYPE: &str = "system_generation";
pub const SYSTEM_RELEASE_BUILDER_CAPABILITY: &str = "system_release_builder_v3";
pub const SYSTEM_RELEASE_BLUEPRINT_INPUT_SCHEMA: &str = "cybex.system-release-blueprint-input.v3";
pub const SYSTEM_RELEASE_BLUEPRINT_PROJECTION_SCHEMA: &str =
    system_release_compiler_v3::PROJECTION_SCHEMA;
pub const SYSTEM_RELEASE_BLUEPRINT_PROJECTION_REVISION: &str =
    system_release_compiler_v3::PROJECTION_REVISION;
pub const SYSTEM_RELEASE_EXPECTED_STATE_PROJECTION_SCHEMA: &str =
    "cybex.system-release-expected-state-projection.v1";
pub const SYSTEM_RELEASE_EXPECTED_STATE_PROJECTION_REVISION: &str =
    "cybex-system-release-expected-state-projection-v1";
pub const SYSTEM_RELEASE_BASELINE_SCHEMA: &str = "cybex.managed-baseline.v1";
pub const SYSTEM_RELEASE_BASELINE_VERSION: &str = "cybex_managed_baseline_v1";
pub const SYSTEM_RELEASE_TRANSITION_PROTOCOL: &str = "verified_releases_v1";
pub const SYSTEM_RELEASE_WATCHDOG_PROTOCOL: &str = "cybex_release_watchdog_v1";
pub const SYSTEM_RELEASE_HEALTH_POLICY_SCHEMA: &str = "cybex.system-release-health-policy.v1";
pub const SYSTEM_RELEASE_MANAGED_AGENT_SCHEMA: &str = "cybex.managed-agent-input.v1";
pub const SYSTEM_RELEASE_CLOSURE_SCHEMA: &str = "cybex.system-release-closure.v1";
pub const SYSTEM_RELEASE_MARKER_SCHEMA: &str = "cybex.system-release-marker.v3";
pub const SYSTEM_RELEASE_PROVENANCE_SCHEMA: &str = "cybex.forge-system-release-provenance.v1";
pub const SYSTEM_RELEASE_SIGNED_OBJECT_SCHEMA: &str = "cybex.signed-canonical-object.v1";
pub const SYSTEM_RELEASE_PROVENANCE_SIGNING_DOMAIN: &str =
    "CYBEX-FORGE-SYSTEM-RELEASE-PROVENANCE-V1";
pub const SYSTEM_RELEASE_COMPILER_VERSION: &str = system_release_compiler_v3::COMPILER_VERSION;

const SYSTEM_RELEASE_COMPILER_RUNTIME_MODULE_NIX: &str =
    include_str!("system_release_blueprint_v3.nix");
const JCS_SAFE_INTEGER_MAX: u64 = 9_007_199_254_740_991;
const MAX_BUILD_SPEC_BYTES: usize = 2 * 1024 * 1024;
const MAX_STRUCTURED_INPUT_BYTES: usize = 1024 * 1024;
const MAX_VALUE_DEPTH: usize = 32;
const MAX_VALUE_NODES: usize = 100_000;
const MAX_STRING_BYTES: usize = 256 * 1024;
const MAX_HEALTH_CHECKS: usize = 64;
const MAX_BASELINE_MODULES: usize = 256;
const MAX_MOUNT_OPTIONS: usize = 64;
pub const MAX_CLOSURE_MEMBERS: usize = 20_000;
pub const MAX_CLOSURE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_CLOSURE_TOTAL_BYTES: u64 = 64 * 1024 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemReleaseBuildSpecV3 {
    pub schema_version: u32,
    pub kind: String,
    pub artifact_type: String,
    pub target: String,
    pub system: String,
    pub input_revision: String,
    pub input_config_hash: String,
    pub organization_id: String,
    pub release_id: String,
    pub release_sequence: u64,
    pub variant_id: String,
    pub forge_artifact_id: String,
    pub cohort_key: String,
    pub baseline_version: String,
    pub compiler_version: String,
    pub nixpkgs_commit: String,
    pub input_manifest_sha256: String,
    pub semantic_input_sha256: String,
    pub blueprint: SystemReleaseBlueprintInputV3,
    pub managed_baseline: ManagedBaselineV1,
    pub managed_baseline_sha256: String,
    pub managed_agent: ManagedAgentInputV1,
    pub health_policy: SystemReleaseHealthPolicyV1,
    pub health_policy_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemReleaseBlueprintInputV3 {
    pub schema: String,
    pub blueprint_id: String,
    pub blueprint_revision_id: String,
    pub policy_revision_id: String,
    pub name: String,
    pub config_schema: String,
    pub config: Value,
    pub config_sha256: String,
    pub source_config_sha256: String,
    pub compiled_module_sha256: String,
    pub asset_manifest: Value,
    pub asset_manifest_sha256: String,
    pub extension_manifest: Value,
    pub extension_manifest_sha256: String,
    pub compiler_runtime_module_sha256: String,
    pub source_expected_state_sha256: String,
    pub expected_state_schema: String,
    pub expected_state: Value,
    pub expected_state_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedBaselineV1 {
    pub schema: String,
    pub version: String,
    pub system: String,
    pub state_version: String,
    pub disk_layout_profile: ManagedDiskLayoutProfile,
    pub boot_mode: ManagedBootMode,
    pub bootloader: ManagedBootloader,
    pub bootloader_device: Option<String>,
    pub root_encryption: ManagedRootEncryptionV1,
    pub root_file_system: ManagedFileSystemV1,
    pub efi_file_system: Option<ManagedFileSystemV1>,
    pub swap_devices: Vec<String>,
    pub initrd_available_kernel_modules: Vec<String>,
    pub initrd_kernel_modules: Vec<String>,
    pub kernel_modules: Vec<String>,
    pub hardware_profile: ManagedHardwareProfileV1,
    pub transition_protocol: String,
    pub watchdog_protocol: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedDiskLayoutProfile {
    SingleDiskGptUefi,
    SingleDiskGptBios,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedBootMode {
    Uefi,
    Bios,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedBootloader {
    SystemdBoot,
    Grub,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedRootEncryptionV1 {
    pub mode: ManagedRootEncryptionMode,
    pub mapper_name: Option<String>,
    pub underlying_device: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedRootEncryptionMode {
    None,
    Luks2,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedFileSystemV1 {
    pub mount_point: String,
    pub device: String,
    pub fs_type: String,
    pub options: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedHardwareProfileV1 {
    pub cpu_architecture: String,
    pub virtualization: String,
    pub graphics_policy: String,
    pub firmware: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedAgentInputV1 {
    pub schema: String,
    pub version: String,
    pub package_sha256: String,
    pub module_sha256: String,
    pub transition_helper_sha256: String,
    pub watchdog_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemReleaseClosureMemberV1 {
    pub store_path: String,
    pub nar_hash: String,
    pub nar_size_bytes: u64,
    pub references: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemReleaseClosureManifestV1 {
    pub schema: String,
    pub organization_id: String,
    pub release_id: String,
    pub variant_id: String,
    pub target_store_path: String,
    pub members: Vec<SystemReleaseClosureMemberV1>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemReleaseMarkerV3 {
    pub schema: String,
    pub organization_id: String,
    pub release_id: String,
    pub release_sequence: u64,
    pub variant_id: String,
    pub cohort_key: String,
    pub system: String,
    pub nixpkgs_commit: String,
    pub baseline_version: String,
    pub compiler_version: String,
    pub managed_agent_version: String,
    pub managed_agent_package_sha256: String,
    pub managed_agent_module_sha256: String,
    pub transition_helper_sha256: String,
    pub watchdog_sha256: String,
    pub input_manifest_sha256: String,
    pub semantic_input_sha256: String,
    pub blueprint_compiled_module_sha256: String,
    pub blueprint_asset_manifest_sha256: String,
    pub blueprint_extension_manifest_sha256: String,
    pub compiler_runtime_module_sha256: String,
    pub health_policy_sha256: String,
    pub expected_state_sha256: String,
}

#[derive(Clone, Debug)]
pub struct AttestationIdentity {
    pub signing_key: SigningKey,
    pub public_key: String,
    pub key_id: String,
}

#[derive(Clone, Debug)]
pub struct TrustedManagedAgentBundle {
    pub package_store_path: String,
    pub module_bytes: Vec<u8>,
    pub transition_helper_bytes: Vec<u8>,
    pub watchdog_bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct CapabilityContext {
    pub forge_node_id: String,
    pub attestation_public_key: String,
    pub attestation_key_id: String,
    pub managed_agent: ManagedAgentInputV1,
}

#[derive(Clone, Debug)]
pub struct RenderedSystemReleaseFile {
    pub name: String,
    pub bytes: Vec<u8>,
    pub mode: u32,
}

#[derive(Clone, Debug)]
pub struct SystemReleaseMaterialBundle {
    pub compiled_blueprint: Vec<u8>,
    pub assets: BTreeMap<String, Vec<u8>>,
    pub extensions: BTreeMap<String, Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct RenderedSystemReleaseInputs {
    pub files: Vec<RenderedSystemReleaseFile>,
    pub release_marker_sha256: String,
}

#[derive(Clone, Debug)]
pub struct PublishedSystemReleaseEvidence {
    pub closure_path: PathBuf,
    pub closure_relative_path: String,
    pub closure_url: String,
    pub provenance_path: PathBuf,
    pub provenance_relative_path: String,
    pub provenance_url: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemReleaseHealthPolicyV1 {
    pub schema: String,
    pub revision: String,
    pub required_checks: Vec<SystemReleaseHealthCheckPolicyV1>,
    pub reconnect_timeout_seconds: u64,
    pub watchdog_timeout_seconds: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemReleaseHealthCheckPolicyV1 {
    pub check_id: String,
    pub kind: SystemReleaseHealthCheckKind,
    pub unit: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SystemReleaseHealthCheckKind {
    ActiveStorePath,
    SystemProfilePath,
    BootDefaultPath,
    AgentReconnected,
    ManageAcceptedReport,
    ExpectedState,
    SystemdUnitActive,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForgeSystemReleaseProvenanceV1 {
    pub schema: String,
    pub organization_id: String,
    pub release_id: String,
    pub variant_id: String,
    pub forge_node_id: String,
    pub forge_build_job_id: String,
    pub forge_artifact_id: String,
    pub forge_protocol: u32,
    pub forge_version: String,
    pub forge_capabilities: Vec<String>,
    pub nixpkgs_commit: String,
    pub nix_version: String,
    pub system: String,
    pub baseline_version: String,
    pub compiler_version: String,
    pub input_manifest_sha256: String,
    pub build_spec_sha256: String,
    pub target_store_path: String,
    pub target_output_sha256: String,
    pub target_nar_hash: String,
    pub target_nar_size_bytes: u64,
    pub target_kernel_store_path: String,
    pub target_initrd_store_path: String,
    pub target_kernel_version: String,
    pub release_marker_sha256: String,
    pub closure_digest_sha256: String,
    pub closure_manifest_sha256: String,
    pub closure_manifest_size_bytes: u64,
    pub closure_member_count: u64,
    pub closure_total_size_bytes: u64,
    pub cache_key_id: String,
    pub cache_key_fingerprint: String,
    pub build_started_at: String,
    pub build_completed_at: String,
    pub result: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedCanonicalObjectV1 {
    pub schema: String,
    pub content_type: String,
    pub organization_id: String,
    pub canonical_sha256: String,
    pub canonical_bytes_b64: String,
    pub signatures: Vec<SystemReleaseSignatureV1>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemReleaseSignatureV1 {
    pub key_id: String,
    pub signature: String,
}

impl SystemReleaseBuildSpecV3 {
    pub fn parse(value: Value) -> Result<Self> {
        let encoded = serde_json::to_vec(&value).context("encode System Release BuildSpec")?;
        if encoded.len() > MAX_BUILD_SPEC_BYTES {
            bail!("System Release BuildSpec exceeds its byte limit");
        }
        validate_structured_value(&value, "System Release BuildSpec")?;
        let spec: Self = serde_json::from_value(value)
            .context("System Release BuildSpec does not match schema v3")?;
        spec.validate()?;
        Ok(spec)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != SYSTEM_RELEASE_BUILD_SPEC_SCHEMA_VERSION
            || self.kind != SYSTEM_RELEASE_BUILD_KIND
            || self.artifact_type != SYSTEM_RELEASE_ARTIFACT_TYPE
            || self.target != SYSTEM_RELEASE_BUILD_TARGET
            || self.compiler_version != SYSTEM_RELEASE_COMPILER_VERSION
        {
            bail!("unsupported System Release BuildSpec identity");
        }
        validate_system(&self.system)?;
        validate_uuid(&self.organization_id, "organization_id")?;
        validate_uuid(&self.release_id, "release_id")?;
        validate_uuid(&self.variant_id, "variant_id")?;
        validate_uuid(&self.forge_artifact_id, "forge_artifact_id")?;
        validate_safe_sequence(self.release_sequence, "release_sequence")?;
        validate_bounded_text(&self.input_revision, 1, 256, "input_revision")?;
        validate_sha256(&self.input_config_hash, "input_config_hash")?;
        validate_sha256(&self.cohort_key, "cohort_key")?;
        validate_bounded_token(&self.baseline_version, 1, 128, "baseline_version")?;
        validate_bounded_token(&self.compiler_version, 1, 128, "compiler_version")?;
        validate_lower_hex(&self.nixpkgs_commit, 40, "nixpkgs_commit")?;
        validate_sha256(&self.input_manifest_sha256, "input_manifest_sha256")?;
        validate_sha256(&self.semantic_input_sha256, "semantic_input_sha256")?;
        if self.input_config_hash != self.input_manifest_sha256 {
            bail!("BuildSpec row hash does not match its immutable input manifest");
        }
        if self.semantic_input_sha256 != self.computed_semantic_input_sha256()? {
            bail!("BuildSpec semantic input digest does not match its canonical semantic fields");
        }
        self.blueprint.validate()?;
        self.managed_baseline.validate()?;
        self.managed_agent.validate()?;
        self.health_policy.validate()?;
        if self.system != self.managed_baseline.system
            || self.baseline_version != self.managed_baseline.version
        {
            bail!("BuildSpec baseline identity does not match the selected system");
        }
        if !matches!(
            (
                self.system.as_str(),
                self.managed_baseline
                    .hardware_profile
                    .cpu_architecture
                    .as_str()
            ),
            ("x86_64-linux", "x86_64") | ("aarch64-linux", "aarch64")
        ) {
            bail!("BuildSpec system and managed-baseline CPU architecture differ");
        }
        let baseline_sha256 = canonical_sha256(&self.managed_baseline, MAX_STRUCTURED_INPUT_BYTES)?;
        let health_sha256 = canonical_sha256(&self.health_policy, MAX_STRUCTURED_INPUT_BYTES)?;
        if self.managed_baseline_sha256 != baseline_sha256
            || self.cohort_key != baseline_sha256
            || self.health_policy_sha256 != health_sha256
        {
            bail!("BuildSpec typed input digest does not match its canonical bytes");
        }
        let projection = system_release_compiler_v3::validate_projection(&self.blueprint.config)
            .map_err(anyhow::Error::msg)?;
        if projection.typed_config["security"]["root_encryption"] != "luks2_required"
            || self.managed_baseline.root_encryption.mode != ManagedRootEncryptionMode::Luks2
        {
            bail!("Blueprint encryption requirement does not match the managed baseline");
        }
        if projection.typed_config["release_control"]["source_os_line"]
            != self.managed_baseline.state_version
            || projection.typed_config["release_control"]["auto_upgrade"] != false
        {
            bail!("Blueprint release controls do not match the pinned managed baseline");
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        canonical_digest_bytes(self, MAX_BUILD_SPEC_BYTES)
    }

    pub fn canonical_sha256(&self) -> Result<String> {
        Ok(sha256_hex(&self.canonical_bytes()?))
    }

    pub fn computed_semantic_input_sha256(&self) -> Result<String> {
        let semantic = json!({
            "schema_version": self.schema_version,
            "kind": self.kind,
            "artifact_type": self.artifact_type,
            "target": self.target,
            "system": self.system,
            "input_revision": self.input_revision,
            "input_config_hash": self.input_config_hash,
            "organization_id": self.organization_id,
            "release_id": self.release_id,
            "release_sequence": self.release_sequence,
            "variant_id": self.variant_id,
            "cohort_key": self.cohort_key,
            "baseline_version": self.baseline_version,
            "compiler_version": self.compiler_version,
            "nixpkgs_commit": self.nixpkgs_commit,
            "input_manifest_sha256": self.input_manifest_sha256,
            "blueprint": self.blueprint,
            "managed_baseline": self.managed_baseline,
            "managed_baseline_sha256": self.managed_baseline_sha256,
            "managed_agent": self.managed_agent,
            "health_policy": self.health_policy,
            "health_policy_sha256": self.health_policy_sha256,
        });
        canonical_value_digest_sha256(&semantic, MAX_BUILD_SPEC_BYTES)
    }
}

impl SystemReleaseBlueprintInputV3 {
    fn validate(&self) -> Result<()> {
        if self.schema != SYSTEM_RELEASE_BLUEPRINT_INPUT_SCHEMA {
            bail!("unsupported System Release Blueprint input schema");
        }
        for (name, value) in [
            ("blueprint_id", self.blueprint_id.as_str()),
            ("blueprint_revision_id", self.blueprint_revision_id.as_str()),
            ("policy_revision_id", self.policy_revision_id.as_str()),
        ] {
            validate_uuid(value, name)?;
        }
        validate_bounded_text(&self.name, 1, 128, "blueprint name")?;
        validate_bounded_token(&self.config_schema, 1, 128, "Blueprint config schema")?;
        validate_bounded_token(&self.expected_state_schema, 1, 128, "expected-state schema")?;
        if self.config_schema != SYSTEM_RELEASE_BLUEPRINT_PROJECTION_SCHEMA
            || self.expected_state_schema != SYSTEM_RELEASE_EXPECTED_STATE_PROJECTION_SCHEMA
        {
            bail!("System Release Blueprint uses an unsupported typed schema");
        }
        if !self.config.is_object() || !self.expected_state.is_object() {
            bail!("Blueprint config and expected state must be structured objects");
        }
        if self.expected_state.get("schema").and_then(Value::as_str)
            != Some(self.expected_state_schema.as_str())
        {
            bail!("expected-state schema field does not match its typed payload");
        }
        validate_structured_digest_value(&self.config, "Blueprint config")?;
        validate_structured_value(&self.expected_state, "expected state")?;
        let derived = system_release_compiler_v3::validate_projection(&self.config)
            .map_err(anyhow::Error::msg)?;
        validate_expected_state_projection(&self.expected_state)?;
        validate_sha256(&self.config_sha256, "Blueprint config SHA-256")?;
        validate_sha256(
            &self.source_config_sha256,
            "Blueprint source config SHA-256",
        )?;
        validate_sha256(
            &self.compiled_module_sha256,
            "compiled Blueprint module SHA-256",
        )?;
        validate_sha256(
            &self.asset_manifest_sha256,
            "Blueprint asset manifest SHA-256",
        )?;
        validate_sha256(
            &self.extension_manifest_sha256,
            "Blueprint extension manifest SHA-256",
        )?;
        validate_sha256(
            &self.compiler_runtime_module_sha256,
            "Blueprint compiler runtime module SHA-256",
        )?;
        if self.compiler_runtime_module_sha256
            != sha256_hex(SYSTEM_RELEASE_COMPILER_RUNTIME_MODULE_NIX.as_bytes())
        {
            bail!(
                "BuildSpec Blueprint runtime digest does not match Forge compiler-v3 local bytes"
            );
        }
        validate_sha256(
            &self.source_expected_state_sha256,
            "Blueprint source expected-state SHA-256",
        )?;
        validate_sha256(&self.expected_state_sha256, "expected-state SHA-256")?;
        validate_structured_digest_value(&self.asset_manifest, "Blueprint asset manifest")?;
        validate_structured_digest_value(&self.extension_manifest, "Blueprint extension manifest")?;
        if canonical_value_digest_sha256(&self.config, MAX_STRUCTURED_INPUT_BYTES)?
            != self.config_sha256
            || self.source_config_sha256 != derived.source_config_sha256
            || derived.asset_manifest != self.asset_manifest
            || derived.extension_manifest != self.extension_manifest
            || canonical_value_digest_sha256(&self.asset_manifest, MAX_STRUCTURED_INPUT_BYTES)?
                != self.asset_manifest_sha256
            || canonical_value_digest_sha256(&self.extension_manifest, MAX_STRUCTURED_INPUT_BYTES)?
                != self.extension_manifest_sha256
            || canonical_value_sha256(&self.expected_state, MAX_STRUCTURED_INPUT_BYTES)?
                != self.expected_state_sha256
            || self
                .expected_state
                .get("source_expected_state_sha256")
                .and_then(Value::as_str)
                != Some(self.source_expected_state_sha256.as_str())
        {
            bail!("Blueprint typed input digest does not match canonical bytes");
        }
        Ok(())
    }
}

fn validate_expected_state_projection(value: &Value) -> Result<()> {
    let object = value
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("expected-state projection is not an object"))?;
    validate_renderer_keys(
        object,
        &[
            "schema",
            "compiler_revision",
            "source_expected_state_sha256",
            "checks",
        ],
        "expected-state projection",
    )?;
    if object.get("schema").and_then(Value::as_str)
        != Some(SYSTEM_RELEASE_EXPECTED_STATE_PROJECTION_SCHEMA)
        || object.get("compiler_revision").and_then(Value::as_str)
            != Some(SYSTEM_RELEASE_EXPECTED_STATE_PROJECTION_REVISION)
    {
        bail!("expected-state projection identity is unsupported");
    }
    let source_digest = object
        .get("source_expected_state_sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("expected-state projection omits its source digest"))?;
    validate_sha256(source_digest, "expected-state projection source")?;
    let checks = object
        .get("checks")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("expected-state projection checks is not an array"))?;
    if checks.is_empty() || checks.len() > 256 {
        bail!("expected-state projection requires 1..=256 checks");
    }
    let mut prior_id: Option<&str> = None;
    for check in checks {
        let check = check
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("expected-state check is not an object"))?;
        validate_renderer_keys(check, &["expected", "id", "kind"], "expected-state check")?;
        let id = check
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("expected-state check omits id"))?;
        validate_bounded_token(id, 1, 128, "expected-state check id")?;
        if prior_id.is_some_and(|prior| prior >= id) {
            bail!("expected-state check IDs must be sorted and unique");
        }
        prior_id = Some(id);
        let kind = check
            .get("kind")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("expected-state check omits kind"))?;
        let expected = check
            .get("expected")
            .and_then(Value::as_object)
            .ok_or_else(|| anyhow::anyhow!("expected-state check omits expected object"))?;
        match kind {
            "local-user-presence" => {
                validate_renderer_keys(expected, &["present", "username"], "local-user expected")?;
                if expected.get("username").and_then(Value::as_str) != Some("cybex-admin")
                    || expected.get("present").and_then(Value::as_bool).is_none()
                {
                    bail!("local-user-presence check is outside the agent contract");
                }
            }
            "dns-resolvers-exclusive" => {
                validate_renderer_keys(expected, &["resolvers"], "DNS expected")?;
                let resolvers = expected
                    .get("resolvers")
                    .and_then(Value::as_array)
                    .ok_or_else(|| anyhow::anyhow!("DNS expected resolvers is not an array"))?;
                if resolvers.is_empty()
                    || resolvers.len() > 8
                    || resolvers.iter().any(|value| {
                        value
                            .as_str()
                            .is_none_or(|value| value.parse::<std::net::IpAddr>().is_err())
                    })
                    || resolvers.windows(2).any(|pair| {
                        pair[0].as_str().unwrap_or_default() >= pair[1].as_str().unwrap_or_default()
                    })
                {
                    bail!("dns-resolvers-exclusive check is outside the agent contract");
                }
            }
            "kconfig-value" => {
                validate_renderer_keys(
                    expected,
                    &["file", "key", "section", "value"],
                    "KConfig expected",
                )?;
                if expected.get("file").and_then(Value::as_str) != Some("/etc/xdg/kdeglobals")
                    || expected.get("section").and_then(Value::as_str) != Some("General")
                    || !matches!(
                        expected.get("key").and_then(Value::as_str),
                        Some("TerminalApplication" | "BrowserApplication")
                    )
                {
                    bail!("kconfig-value check is outside the agent contract");
                }
                validate_bounded_text(
                    expected
                        .get("value")
                        .and_then(Value::as_str)
                        .ok_or_else(|| anyhow::anyhow!("KConfig expected value is not a string"))?,
                    1,
                    256,
                    "KConfig expected value",
                )?;
            }
            "systemd-unit-enabled" => {
                validate_renderer_keys(expected, &["enabled", "unit"], "systemd expected")?;
                if expected.get("unit").and_then(Value::as_str) != Some("docker.service")
                    || expected.get("enabled").and_then(Value::as_bool).is_none()
                {
                    bail!("systemd-unit-enabled check is outside the agent contract");
                }
            }
            "file-sha256" => {
                validate_renderer_keys(
                    expected,
                    &["path", "sha256", "size_bytes"],
                    "file digest expected",
                )?;
                let path = expected
                    .get("path")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow::anyhow!("file digest path is missing"))?;
                if !valid_expected_file_path(path)
                    || expected
                        .get("size_bytes")
                        .and_then(Value::as_u64)
                        .is_none_or(|size| size > 1024 * 1024)
                {
                    bail!("file-sha256 check is outside the agent contract");
                }
                validate_sha256(
                    expected
                        .get("sha256")
                        .and_then(Value::as_str)
                        .ok_or_else(|| anyhow::anyhow!("file digest is missing"))?,
                    "expected file SHA-256",
                )?;
            }
            _ => bail!("expected-state check kind is unsupported by the managed agent"),
        }
    }
    Ok(())
}

fn valid_expected_file_path(path: &str) -> bool {
    if path.is_empty()
        || path.len() > 4096
        || path.ends_with('/')
        || path.contains("//")
        || path.contains('\\')
        || path.chars().any(char::is_control)
        || path
            .split('/')
            .any(|component| matches!(component, "." | ".."))
    {
        return false;
    }
    if path.starts_with("/etc/cybex/blueprint-assets/") {
        return true;
    }
    let Some(remainder) = path.strip_prefix("/home/") else {
        return false;
    };
    let Some((user, relative)) = remainder.split_once('/') else {
        return false;
    };
    !relative.is_empty()
        && !user.is_empty()
        && user.len() <= 32
        && user.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (index > 0 && matches!(byte, b'_' | b'-'))
        })
}

impl ManagedBaselineV1 {
    fn validate(&self) -> Result<()> {
        if self.schema != SYSTEM_RELEASE_BASELINE_SCHEMA
            || self.version != SYSTEM_RELEASE_BASELINE_VERSION
            || self.state_version != "26.05"
            || self.transition_protocol != SYSTEM_RELEASE_TRANSITION_PROTOCOL
            || self.watchdog_protocol != SYSTEM_RELEASE_WATCHDOG_PROTOCOL
        {
            bail!("unsupported managed baseline schema");
        }
        validate_system(&self.system)?;
        match (
            self.disk_layout_profile,
            self.boot_mode,
            self.bootloader,
            self.efi_file_system.as_ref(),
        ) {
            (
                ManagedDiskLayoutProfile::SingleDiskGptUefi,
                ManagedBootMode::Uefi,
                ManagedBootloader::Grub | ManagedBootloader::SystemdBoot,
                Some(efi),
            ) if self.bootloader_device.is_none() => {
                efi.validate_efi()?;
            }
            (
                ManagedDiskLayoutProfile::SingleDiskGptBios,
                ManagedBootMode::Bios,
                ManagedBootloader::Grub,
                None,
            ) if self.system == "x86_64-linux"
                && self
                    .bootloader_device
                    .as_deref()
                    .is_some_and(valid_managed_baseline_whole_disk) => {}
            _ => bail!("managed baseline boot mode and bootloader are inconsistent"),
        }
        self.root_file_system.validate_root()?;
        match self.root_encryption.mode {
            ManagedRootEncryptionMode::None => {
                if self.root_encryption.mapper_name.is_some()
                    || self.root_encryption.underlying_device.is_some()
                    || !(valid_managed_baseline_uuid_device(&self.root_file_system.device)
                        || valid_managed_baseline_label_device(&self.root_file_system.device))
                {
                    bail!("managed baseline unencrypted root identity is invalid");
                }
            }
            ManagedRootEncryptionMode::Luks2 => {
                if self.root_encryption.mapper_name.as_deref() != Some("cybex-root")
                    || self.root_encryption.underlying_device.as_deref()
                        != Some("/dev/disk/by-partlabel/CYBEX-NIXOS")
                    || self.root_file_system.device != "/dev/mapper/cybex-root"
                {
                    bail!("managed baseline LUKS2 root identity is invalid");
                }
            }
        }
        validate_sorted_unique_baseline_values(&self.swap_devices, 32, "swap devices")?;
        if !self.swap_devices.iter().all(|value| {
            valid_managed_baseline_uuid_device(value) || valid_managed_baseline_mapper_device(value)
        }) {
            bail!("managed baseline swap device is unsupported");
        }
        for (values, label) in [
            (
                &self.initrd_available_kernel_modules,
                "initrd available kernel modules",
            ),
            (&self.initrd_kernel_modules, "initrd kernel modules"),
            (&self.kernel_modules, "kernel modules"),
        ] {
            validate_sorted_unique_baseline_values(values, MAX_BASELINE_MODULES, label)?;
            if !values
                .iter()
                .all(|module| valid_managed_baseline_module(module))
            {
                bail!("{label} contains a module outside compiler v1");
            }
        }
        self.hardware_profile.validate()?;
        let expected_architecture = match self.system.as_str() {
            "x86_64-linux" => "x86_64",
            "aarch64-linux" => "aarch64",
            _ => unreachable!(),
        };
        if self.hardware_profile.cpu_architecture != expected_architecture {
            bail!("managed baseline system and CPU architecture differ");
        }
        if self
            .initrd_available_kernel_modules
            .iter()
            .chain(&self.initrd_kernel_modules)
            .chain(&self.kernel_modules)
            .any(|module| module.starts_with("nvidia"))
            && self.hardware_profile.graphics_policy != "nvidia_proprietary"
        {
            bail!("managed baseline Nvidia modules require the Nvidia profile");
        }
        Ok(())
    }
}

impl ManagedFileSystemV1 {
    fn validate_root(&self) -> Result<()> {
        if self.mount_point != "/"
            || !matches!(self.fs_type.as_str(), "btrfs" | "ext4" | "xfs" | "f2fs")
        {
            bail!("managed baseline root filesystem is unsupported");
        }
        validate_sorted_unique_baseline_values(&self.options, MAX_MOUNT_OPTIONS, "mount options")?;
        if !self
            .options
            .iter()
            .all(|option| valid_managed_baseline_root_option(option, &self.fs_type))
        {
            bail!("managed baseline root filesystem option is unsupported");
        }
        Ok(())
    }

    fn validate_efi(&self) -> Result<()> {
        if !matches!(self.mount_point.as_str(), "/boot" | "/boot/efi")
            || self.fs_type != "vfat"
            || !(valid_managed_baseline_uuid_device(&self.device)
                || valid_managed_baseline_label_device(&self.device))
        {
            bail!("managed baseline EFI filesystem is unsupported");
        }
        validate_sorted_unique_baseline_values(&self.options, MAX_MOUNT_OPTIONS, "mount options")?;
        if !self
            .options
            .iter()
            .all(|option| valid_managed_baseline_efi_option(option))
        {
            bail!("managed baseline EFI filesystem option is unsupported");
        }
        Ok(())
    }
}

impl ManagedHardwareProfileV1 {
    fn validate(&self) -> Result<()> {
        if !matches!(self.cpu_architecture.as_str(), "x86_64" | "aarch64")
            || !matches!(
                self.virtualization.as_str(),
                "none" | "kvm" | "vmware" | "hyperv" | "virtualbox"
            )
            || !matches!(
                self.graphics_policy.as_str(),
                "open_graphics" | "nvidia_proprietary"
            )
            || !matches!(self.firmware.as_str(), "redistributable" | "all")
        {
            bail!("managed baseline hardware profile is unsupported");
        }
        Ok(())
    }
}

impl ManagedAgentInputV1 {
    fn validate(&self) -> Result<()> {
        if self.schema != SYSTEM_RELEASE_MANAGED_AGENT_SCHEMA {
            bail!("unsupported managed-agent input schema");
        }
        validate_bounded_token(&self.version, 1, 128, "managed-agent version")?;
        for (name, digest) in [
            ("managed-agent package", self.package_sha256.as_str()),
            ("managed-agent module", self.module_sha256.as_str()),
            (
                "managed-agent transition helper",
                self.transition_helper_sha256.as_str(),
            ),
            ("managed-agent watchdog", self.watchdog_sha256.as_str()),
        ] {
            validate_sha256(digest, name)?;
        }
        Ok(())
    }
}

impl SystemReleaseHealthPolicyV1 {
    fn validate(&self) -> Result<()> {
        if self.schema != SYSTEM_RELEASE_HEALTH_POLICY_SCHEMA {
            bail!("unsupported System Release health policy schema");
        }
        validate_bounded_token(&self.revision, 1, 128, "health policy revision")?;
        if self.required_checks.is_empty() || self.required_checks.len() > MAX_HEALTH_CHECKS {
            bail!("System Release health policy check count is invalid");
        }
        if !(30..=3600).contains(&self.reconnect_timeout_seconds)
            || !(60..=7200).contains(&self.watchdog_timeout_seconds)
            || self.watchdog_timeout_seconds <= self.reconnect_timeout_seconds
        {
            bail!("System Release health policy timeout is invalid");
        }
        let mut previous: Option<&str> = None;
        let mut required_kinds = BTreeSet::new();
        for check in &self.required_checks {
            validate_bounded_token(&check.check_id, 1, 64, "health check ID")?;
            if previous.is_some_and(|value| value >= check.check_id.as_str()) {
                bail!("System Release health checks are not uniquely sorted");
            }
            previous = Some(&check.check_id);
            match check.kind {
                SystemReleaseHealthCheckKind::SystemdUnitActive => {
                    let unit = check
                        .unit
                        .as_deref()
                        .ok_or_else(|| anyhow::anyhow!("systemd health check requires a unit"))?;
                    validate_systemd_unit(unit)?;
                }
                _ if check.unit.is_some() => bail!("non-systemd health check must not name a unit"),
                _ => {}
            }
            required_kinds.insert(format!("{:?}", check.kind));
        }
        for kind in [
            SystemReleaseHealthCheckKind::ActiveStorePath,
            SystemReleaseHealthCheckKind::SystemProfilePath,
            SystemReleaseHealthCheckKind::BootDefaultPath,
            SystemReleaseHealthCheckKind::AgentReconnected,
            SystemReleaseHealthCheckKind::ManageAcceptedReport,
            SystemReleaseHealthCheckKind::ExpectedState,
        ] {
            if !required_kinds.contains(&format!("{kind:?}")) {
                bail!("System Release health policy omits a mandatory check");
            }
        }
        Ok(())
    }
}

impl ForgeSystemReleaseProvenanceV1 {
    pub fn validate(&self) -> Result<()> {
        if self.schema != SYSTEM_RELEASE_PROVENANCE_SCHEMA
            || self.forge_protocol != SYSTEM_RELEASE_FORGE_PROTOCOL
            || self.result != "succeeded"
        {
            bail!("unsupported Forge System Release provenance identity");
        }
        for (name, value) in [
            ("organization_id", self.organization_id.as_str()),
            ("release_id", self.release_id.as_str()),
            ("variant_id", self.variant_id.as_str()),
            ("forge_build_job_id", self.forge_build_job_id.as_str()),
            ("forge_artifact_id", self.forge_artifact_id.as_str()),
        ] {
            validate_uuid(value, name)?;
        }
        validate_bounded_token(&self.forge_node_id, 1, 256, "Forge node ID")?;
        validate_bounded_token(&self.forge_version, 1, 128, "Forge version")?;
        validate_bounded_token(&self.nix_version, 1, 128, "Nix version")?;
        validate_system(&self.system)?;
        validate_bounded_token(&self.baseline_version, 1, 128, "baseline version")?;
        if self.compiler_version != SYSTEM_RELEASE_COMPILER_VERSION {
            bail!("Forge provenance compiler version is unsupported");
        }
        validate_lower_hex(&self.nixpkgs_commit, 40, "nixpkgs commit")?;
        validate_sorted_unique_tokens(&self.forge_capabilities, 32, "Forge capabilities")?;
        if self
            .forge_capabilities
            .binary_search_by(|value| value.as_str().cmp(SYSTEM_RELEASE_BUILDER_CAPABILITY))
            .is_err()
        {
            bail!("Forge provenance omits system_release_builder_v3");
        }
        for (name, digest) in [
            ("input manifest", self.input_manifest_sha256.as_str()),
            ("BuildSpec", self.build_spec_sha256.as_str()),
            ("target output", self.target_output_sha256.as_str()),
            ("release marker", self.release_marker_sha256.as_str()),
            ("closure", self.closure_digest_sha256.as_str()),
            ("closure manifest", self.closure_manifest_sha256.as_str()),
            ("cache key", self.cache_key_id.as_str()),
            ("cache key fingerprint", self.cache_key_fingerprint.as_str()),
        ] {
            validate_sha256(digest, name)?;
        }
        validate_store_path(&self.target_store_path)?;
        validate_store_path(&self.target_kernel_store_path)?;
        validate_store_path(&self.target_initrd_store_path)?;
        validate_bounded_text(&self.target_kernel_version, 1, 128, "target kernel version")?;
        if self.target_kernel_version.trim() != self.target_kernel_version {
            bail!("target kernel version is not canonical");
        }
        validate_nar_hash(&self.target_nar_hash)?;
        if self.target_nar_size_bytes == 0
            || self.closure_manifest_size_bytes == 0
            || self.closure_member_count == 0
            || self.closure_member_count > u64::try_from(MAX_CLOSURE_MEMBERS).unwrap_or(u64::MAX)
            || self.closure_total_size_bytes == 0
        {
            bail!("Forge provenance closure sizes are invalid");
        }
        let started = parse_canonical_time(&self.build_started_at)?;
        let completed = parse_canonical_time(&self.build_completed_at)?;
        if completed <= started {
            bail!("Forge provenance build window is invalid");
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        canonical_bytes(self, MAX_STRUCTURED_INPUT_BYTES)
    }
}

pub fn sign_provenance(
    provenance: &ForgeSystemReleaseProvenanceV1,
    signing_key: &SigningKey,
) -> Result<SignedCanonicalObjectV1> {
    let canonical = provenance.canonical_bytes()?;
    let organization_id = validate_uuid(&provenance.organization_id, "organization_id")?;
    let canonical_sha256 = sha256_hex(&canonical);
    let message = signing_message(
        SYSTEM_RELEASE_PROVENANCE_SIGNING_DOMAIN,
        organization_id,
        &canonical,
    )?;
    let key_id = sha256_hex(&signing_key.verifying_key().to_bytes());
    Ok(SignedCanonicalObjectV1 {
        schema: SYSTEM_RELEASE_SIGNED_OBJECT_SCHEMA.to_string(),
        content_type: SYSTEM_RELEASE_PROVENANCE_SCHEMA.to_string(),
        organization_id: provenance.organization_id.clone(),
        canonical_sha256,
        canonical_bytes_b64: URL_SAFE_NO_PAD.encode(canonical),
        signatures: vec![SystemReleaseSignatureV1 {
            key_id,
            signature: URL_SAFE_NO_PAD.encode(signing_key.sign(&message).to_bytes()),
        }],
    })
}

impl SignedCanonicalObjectV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        if self.schema != SYSTEM_RELEASE_SIGNED_OBJECT_SCHEMA
            || self.content_type != SYSTEM_RELEASE_PROVENANCE_SCHEMA
            || self.signatures.len() != 1
        {
            bail!("signed provenance envelope identity is invalid");
        }
        validate_uuid(&self.organization_id, "envelope organization_id")?;
        validate_sha256(&self.canonical_sha256, "envelope canonical SHA-256")?;
        let canonical = URL_SAFE_NO_PAD
            .decode(&self.canonical_bytes_b64)
            .context("decode envelope canonical bytes")?;
        if canonical.is_empty()
            || canonical.len() > MAX_STRUCTURED_INPUT_BYTES
            || URL_SAFE_NO_PAD.encode(&canonical) != self.canonical_bytes_b64
            || sha256_hex(&canonical) != self.canonical_sha256
        {
            bail!("signed provenance envelope canonical bytes are invalid");
        }
        validate_sha256(&self.signatures[0].key_id, "attestation key ID")?;
        let signature = URL_SAFE_NO_PAD
            .decode(&self.signatures[0].signature)
            .context("decode provenance signature")?;
        if signature.len() != 64
            || URL_SAFE_NO_PAD.encode(signature) != self.signatures[0].signature
        {
            bail!("provenance signature encoding is invalid");
        }
        canonical_bytes(self, 4 * 1024 * 1024)
    }
}

pub fn publish_system_release_evidence(
    config: &AppConfig,
    spec: &SystemReleaseBuildSpecV3,
    closure_bytes: &[u8],
    provenance_envelope_bytes: &[u8],
) -> Result<PublishedSystemReleaseEvidence> {
    spec.validate()?;
    if closure_bytes.is_empty()
        || closure_bytes.len() > MAX_CLOSURE_BYTES
        || provenance_envelope_bytes.is_empty()
        || provenance_envelope_bytes.len() > 4 * 1024 * 1024
    {
        bail!("System Release evidence exceeds its publication bounds");
    }
    let relative_dir = format!(
        "system-releases/{}/{}/{}/{}",
        spec.organization_id, spec.release_id, spec.variant_id, spec.forge_artifact_id
    );
    let root = &config.cache.root_dir;
    let directory = root.join(&relative_dir);
    let closure_path = directory.join("closure.json");
    let provenance_path = directory.join("provenance-envelope.json");
    if directory.exists() {
        create_public_evidence_directory(root, &directory)?;
        validate_existing_evidence(&closure_path, closure_bytes)?;
        validate_existing_evidence(&provenance_path, provenance_envelope_bytes)?;
    } else {
        let parent = directory
            .parent()
            .ok_or_else(|| anyhow::anyhow!("System Release evidence directory has no parent"))?;
        create_public_evidence_directory(root, parent)?;
        let mut random = [0u8; 8];
        OsRng.fill_bytes(&mut random);
        let staging = parent.join(format!(
            ".{}.{}.{}.tmp",
            spec.forge_artifact_id,
            std::process::id(),
            hex::encode(random)
        ));
        let result: Result<()> = (|| {
            fs::create_dir(&staging).with_context(|| {
                format!("create private evidence staging {}", staging.display())
            })?;
            fs::set_permissions(&staging, fs::Permissions::from_mode(0o700))?;
            let staging_closure = staging.join("closure.json");
            let staging_provenance = staging.join("provenance-envelope.json");
            publish_immutable_file(&staging_closure, closure_bytes)?;
            publish_immutable_file(&staging_provenance, provenance_envelope_bytes)?;
            File::open(&staging)
                .with_context(|| format!("open private evidence staging {}", staging.display()))?
                .sync_all()
                .with_context(|| format!("sync private evidence staging {}", staging.display()))?;
            // The complete directory becomes publicly traversable immediately
            // before its single atomic rename into the served namespace.
            fs::set_permissions(&staging, fs::Permissions::from_mode(0o755))?;
            fs::rename(&staging, &directory).with_context(|| {
                format!(
                    "atomically publish complete System Release evidence {}",
                    directory.display()
                )
            })?;
            sync_parent(&directory)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(&staging);
        }
        result?;
    }
    let closure_relative_path = format!("{relative_dir}/closure.json");
    let provenance_relative_path = format!("{relative_dir}/provenance-envelope.json");
    let cache_base = crate::cache::cache_base_url(config);
    Ok(PublishedSystemReleaseEvidence {
        closure_path,
        closure_url: format!("{cache_base}/{closure_relative_path}"),
        closure_relative_path,
        provenance_path,
        provenance_url: format!("{cache_base}/{provenance_relative_path}"),
        provenance_relative_path,
    })
}

pub(crate) fn load_published_system_release_closure(
    config: &AppConfig,
    organization_id: &str,
    release_id: &str,
    variant_id: &str,
    artifact_id: &str,
    reported_relative_path: &str,
    reported_path: &str,
    expected_size: usize,
    expected_sha256: &str,
) -> Result<Vec<u8>> {
    for (value, field) in [
        (organization_id, "closure organization ID"),
        (release_id, "closure release ID"),
        (variant_id, "closure variant ID"),
        (artifact_id, "closure artifact ID"),
    ] {
        validate_uuid(value, field)?;
    }
    validate_sha256(expected_sha256, "closure upload SHA-256")?;
    if !(2..=MAX_CLOSURE_BYTES).contains(&expected_size) {
        bail!("closure upload size is outside its protocol bound");
    }
    let expected_relative_path = format!(
        "system-releases/{organization_id}/{release_id}/{variant_id}/{artifact_id}/closure.json"
    );
    let expected_path = config.cache.root_dir.join(&expected_relative_path);
    if reported_relative_path != expected_relative_path
        || Path::new(reported_path) != expected_path.as_path()
    {
        bail!("closure upload path is not the exact published evidence path");
    }
    let metadata = fs::symlink_metadata(&expected_path)
        .with_context(|| format!("inspect published closure {}", expected_path.display()))?;
    validate_published_evidence_file(&expected_path, &metadata)?;
    if usize::try_from(metadata.len()).ok() != Some(expected_size) {
        bail!("published closure size changed before upload");
    }
    let bytes = fs::read(&expected_path)
        .with_context(|| format!("read published closure {}", expected_path.display()))?;
    if bytes.len() != expected_size || sha256_hex(&bytes) != expected_sha256 {
        bail!("published closure digest changed before upload");
    }
    let closure: SystemReleaseClosureManifestV1 =
        serde_json::from_slice(&bytes).context("parse published closure before upload")?;
    closure.validate()?;
    if closure.organization_id != organization_id
        || closure.release_id != release_id
        || closure.variant_id != variant_id
        || closure.canonical_bytes()? != bytes
    {
        bail!("published closure identity changed before upload");
    }
    Ok(bytes)
}

fn validate_existing_evidence(path: &Path, expected: &[u8]) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("stat immutable System Release evidence {}", path.display()))?;
    validate_published_evidence_file(path, &metadata)?;
    let existing = fs::read(path)
        .with_context(|| format!("read immutable System Release evidence {}", path.display()))?;
    if existing != expected {
        bail!("refusing to replace immutable System Release evidence");
    }
    Ok(())
}

fn create_public_evidence_directory(root: &Path, directory: &Path) -> Result<()> {
    fs::create_dir_all(root).with_context(|| format!("create cache root {}", root.display()))?;
    let root_metadata = fs::symlink_metadata(root)?;
    let effective_uid = unsafe { libc::geteuid() };
    if !root_metadata.is_dir()
        || root_metadata.file_type().is_symlink()
        || (root_metadata.uid() != 0 && root_metadata.uid() != effective_uid)
        || root_metadata.mode() & 0o022 != 0
    {
        bail!("System Release evidence cache root is unsafe");
    }
    let relative = directory
        .strip_prefix(root)
        .map_err(|_| anyhow::anyhow!("System Release evidence escaped the cache root"))?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let std::path::Component::Normal(component) = component else {
            bail!("System Release evidence path is unsafe");
        };
        current.push(component);
        if !current.exists() {
            fs::create_dir(&current)
                .with_context(|| format!("create evidence directory {}", current.display()))?;
            fs::set_permissions(&current, fs::Permissions::from_mode(0o755))?;
        }
        let metadata = fs::symlink_metadata(&current)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || (metadata.uid() != 0 && metadata.uid() != effective_uid)
            || metadata.mode() & 0o022 != 0
        {
            bail!("System Release evidence directory is unsafe");
        }
    }
    Ok(())
}

fn publish_immutable_file(path: &Path, contents: &[u8]) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            validate_published_evidence_file(path, &metadata)?;
            let existing = fs::read(path).with_context(|| format!("read {}", path.display()))?;
            if existing == contents {
                return Ok(());
            }
            bail!("refusing to replace immutable System Release evidence");
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).with_context(|| format!("stat {}", path.display())),
    }
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("evidence path has no parent"))?;
    let name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("evidence path has no filename"))?
        .to_string_lossy();
    let mut random = [0u8; 8];
    OsRng.fill_bytes(&mut random);
    let temporary = parent.join(format!(
        ".{name}.{}.{}.tmp",
        std::process::id(),
        hex::encode(random)
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o644)
            .open(&temporary)
            .with_context(|| format!("create {}", temporary.display()))?;
        file.set_permissions(fs::Permissions::from_mode(0o644))?;
        file.write_all(contents)?;
        file.sync_all()?;
        drop(file);
        match fs::hard_link(&temporary, path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let metadata = fs::symlink_metadata(path)?;
                validate_published_evidence_file(path, &metadata)?;
                let existing = fs::read(path)?;
                if existing != contents {
                    bail!(
                        "immutable System Release evidence publication raced with different bytes"
                    );
                }
            }
            Err(error) => return Err(error).context("atomically publish System Release evidence"),
        }
        fs::remove_file(&temporary)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn validate_published_evidence_file(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    let effective_uid = unsafe { libc::geteuid() };
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || (metadata.uid() != 0 && metadata.uid() != effective_uid)
        || metadata.mode() & 0o777 != 0o644
    {
        bail!(
            "published System Release evidence {} has unsafe ownership, type, or mode",
            path.display()
        );
    }
    Ok(())
}

pub fn build_spec_sha256(value: &Value) -> Result<String> {
    SystemReleaseBuildSpecV3::parse(value.clone())?.canonical_sha256()
}

pub fn render_system_release_inputs(
    config: &AppConfig,
    spec: &SystemReleaseBuildSpecV3,
    materials: &SystemReleaseMaterialBundle,
) -> Result<RenderedSystemReleaseInputs> {
    spec.validate()?;
    capability_context(config)?;
    let bundle = verify_trusted_managed_agent_bundle(config, &spec.managed_agent)?;
    let marker = SystemReleaseMarkerV3::from_spec(spec)?;
    let marker_bytes = marker.canonical_bytes()?;
    let release_marker_sha256 = sha256_hex(&marker_bytes);
    let blueprint_config =
        canonical_value_digest_bytes(&spec.blueprint.config, MAX_STRUCTURED_INPUT_BYTES)?;
    validate_blueprint_render_allowlist(&spec.blueprint.config)?;
    let compiled_blueprint = materials.compiled_blueprint.clone();
    let compiler_runtime = SYSTEM_RELEASE_COMPILER_RUNTIME_MODULE_NIX
        .as_bytes()
        .to_vec();
    if sha256_hex(&compiled_blueprint) != spec.blueprint.compiled_module_sha256
        || sha256_hex(&compiler_runtime) != spec.blueprint.compiler_runtime_module_sha256
    {
        bail!("downloaded Blueprint module or local runtime fails its BuildSpec digest");
    }
    let (asset_module, mut material_files) =
        render_blueprint_materials(&spec.blueprint, materials)?;
    let (extension_module, extension_files) =
        render_blueprint_extensions(&spec.blueprint, materials)?;
    material_files.extend(extension_files);
    let expected_state =
        canonical_value_bytes(&spec.blueprint.expected_state, MAX_STRUCTURED_INPUT_BYTES)?;
    let baseline = canonical_bytes(&spec.managed_baseline, MAX_STRUCTURED_INPUT_BYTES)?;
    let health_policy = canonical_bytes(&spec.health_policy, MAX_STRUCTURED_INPUT_BYTES)?;
    let managed_agent = canonical_bytes(&spec.managed_agent, MAX_STRUCTURED_INPUT_BYTES)?;
    let package_path = format!("{}\n", bundle.package_store_path).into_bytes();
    let configuration = SYSTEM_RELEASE_CONFIGURATION_NIX.as_bytes().to_vec();
    let flake = system_release_flake(spec).into_bytes();
    let mut files = vec![
        rendered_file("blueprint-config.json", blueprint_config, 0o600),
        rendered_file("compiled-blueprint.nix", compiled_blueprint, 0o600),
        rendered_file("blueprint-assets.nix", asset_module, 0o600),
        rendered_file("blueprint-extensions.nix", extension_module, 0o600),
        rendered_file("blueprint-compiler-runtime.nix", compiler_runtime, 0o600),
        rendered_file("expected-state.json", expected_state, 0o600),
        rendered_file("managed-baseline.json", baseline, 0o600),
        rendered_file("health-policy.json", health_policy, 0o600),
        rendered_file("managed-agent.json", managed_agent, 0o600),
        rendered_file("release-marker.json", marker_bytes, 0o600),
        rendered_file("managed-agent-package-path", package_path, 0o600),
        rendered_file("managed-agent.nix", bundle.module_bytes, 0o600),
        rendered_file(
            "cybex-release-transition.sh",
            bundle.transition_helper_bytes,
            0o700,
        ),
        rendered_file("cybex-release-watchdog.sh", bundle.watchdog_bytes, 0o700),
        rendered_file("configuration.nix", configuration, 0o600),
        rendered_file("flake.nix", flake, 0o600),
    ];
    files.extend(material_files);
    reject_production_test_hook_material(&files)?;
    Ok(RenderedSystemReleaseInputs {
        files,
        release_marker_sha256,
    })
}

fn rendered_file(name: impl Into<String>, bytes: Vec<u8>, mode: u32) -> RenderedSystemReleaseFile {
    RenderedSystemReleaseFile {
        name: name.into(),
        bytes,
        mode,
    }
}

fn reject_production_test_hook_material(files: &[RenderedSystemReleaseFile]) -> Result<()> {
    if files
        .iter()
        .any(|file| file.name == "cybex-release-test-hook.sh")
    {
        bail!("production System Release inputs must not contain a destructive test hook");
    }
    Ok(())
}

fn system_release_flake(spec: &SystemReleaseBuildSpecV3) -> String {
    format!(
        r#"{{
  description = "Cybex Verified System Release";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/{nixpkgs_commit}";

  outputs = {{ self, nixpkgs }}:
    let
      system = "{system}";
      packagePath = builtins.replaceStrings [ "\n" ] [ "" ]
        (builtins.readFile ./managed-agent-package-path);
      cybexManagedAgentPackage = builtins.storePath packagePath;
    in {{
      packages.${{system}}.system-release =
        (nixpkgs.lib.nixosSystem {{
          inherit system;
          specialArgs = {{
            inherit cybexManagedAgentPackage;
          }};
          modules = [ ./configuration.nix ];
        }}).config.system.build.toplevel;
    }};
}}
"#,
        nixpkgs_commit = spec.nixpkgs_commit,
        system = spec.system,
    )
}

const SYSTEM_RELEASE_CONFIGURATION_NIX: &str = r#"{ config, lib, pkgs, cybexManagedAgentPackage, ... }:
let
  baseline = builtins.fromJSON (builtins.readFile ./managed-baseline.json);
  marker = builtins.fromJSON (builtins.readFile ./release-marker.json);
  efi = baseline.efi_file_system;
  useSystemdBoot = baseline.bootloader == "systemd_boot";
  useGrub = baseline.bootloader == "grub";
  grubDevice = if baseline.boot_mode == "uefi"
    then "nodev"
    else baseline.bootloader_device;
in
{
  imports = [
    ./blueprint-compiler-runtime.nix
    ./compiled-blueprint.nix
    ./blueprint-assets.nix
    ./blueprint-extensions.nix
    ./managed-agent.nix
  ];

  assertions = [
    { assertion = baseline.system == marker.system;
      message = "Cybex managed baseline system does not match the release marker"; }
    { assertion = baseline.version == marker.baseline_version;
      message = "Cybex managed baseline version does not match the release marker"; }
    { assertion = config.nixpkgs.hostPlatform.system == marker.system;
      message = "Cybex NixOS host platform does not match the release marker"; }
    { assertion = marker.compiler_version == "cybex-system-release-compiler-v3";
      message = "Cybex System Release compiler binding is unsupported"; }
  ];

  system.stateVersion = baseline.state_version;
  system.autoUpgrade.enable = lib.mkForce false;
  systemd.services.nixos-upgrade.enable = false;
  systemd.timers.nixos-upgrade.enable = false;
  networking.useDHCP = lib.mkDefault true;

  fileSystems = {
    "/" = {
      device = baseline.root_file_system.device;
      fsType = baseline.root_file_system.fs_type;
      options = baseline.root_file_system.options;
    };
  } // lib.optionalAttrs (efi != null) {
    "${efi.mount_point}" = {
      device = efi.device;
      fsType = efi.fs_type;
      options = efi.options;
    };
  };
  swapDevices = map (device: { inherit device; }) baseline.swap_devices;

  boot.loader.systemd-boot.enable = useSystemdBoot;
  boot.loader.systemd-boot.configurationLimit = lib.mkDefault 20;
  boot.loader.grub.enable = useGrub;
  boot.loader.grub.configurationLimit = lib.mkDefault 20;
  boot.loader.grub.efiSupport = useGrub && baseline.boot_mode == "uefi";
  boot.loader.grub.efiInstallAsRemovable = false;
  boot.loader.grub.device = grubDevice;
  boot.loader.grub.devices = lib.optional useGrub grubDevice;
  boot.loader.efi.canTouchEfiVariables = baseline.boot_mode == "uefi";
  boot.loader.efi.efiSysMountPoint = if efi == null then "/boot" else efi.mount_point;
  boot.initrd.luks.devices = lib.optionalAttrs (baseline.root_encryption.mode == "luks2") {
    "cybex-root" = {
      device = baseline.root_encryption.underlying_device;
    };
  };
  boot.initrd.availableKernelModules = baseline.initrd_available_kernel_modules;
  boot.initrd.kernelModules = baseline.initrd_kernel_modules;
  boot.kernelModules = baseline.kernel_modules;

  hardware.enableRedistributableFirmware = baseline.hardware_profile.firmware == "redistributable";
  hardware.enableAllFirmware = baseline.hardware_profile.firmware == "all";
  hardware.graphics.enable = true;
  nixpkgs.config.allowUnfree = baseline.hardware_profile.graphics_policy == "nvidia_proprietary"
    || baseline.hardware_profile.firmware == "all";
  services.qemuGuest.enable = baseline.hardware_profile.virtualization == "kvm";
  virtualisation.vmware.guest.enable = baseline.hardware_profile.virtualization == "vmware";
  virtualisation.hypervGuest.enable = baseline.hardware_profile.virtualization == "hyperv";
  virtualisation.virtualbox.guest.enable = baseline.hardware_profile.virtualization == "virtualbox";

  services.xserver.videoDrivers = lib.optional
    (baseline.hardware_profile.graphics_policy == "nvidia_proprietary") "nvidia";

  environment.systemPackages = [ cybexManagedAgentPackage ];
  services.cybex-agent = {
    enable = true;
    package = cybexManagedAgentPackage;
    configPath = "/var/lib/cybex-agent/config.toml";
    organizationId = marker.organization_id;
    enableVerifiedReleases = true;
  };
  environment.etc."cybex/system-release/release-marker.json".source = ./release-marker.json;
  environment.etc."cybex/system-release/blueprint-config.json".source = ./blueprint-config.json;
  environment.etc."cybex/system-release/expected-state.json".source = ./expected-state.json;
  environment.etc."cybex/system-release/managed-baseline.json".source = ./managed-baseline.json;
  environment.etc."cybex/system-release/health-policy.json".source = ./health-policy.json;
  environment.etc."cybex/system-release/managed-agent.json".source = ./managed-agent.json;
}
"#;

impl SystemReleaseClosureManifestV1 {
    pub fn from_nix_path_info(
        spec: &SystemReleaseBuildSpecV3,
        target_store_path: &str,
        value: &Value,
    ) -> Result<Self> {
        validate_store_path(target_store_path)?;
        let rows = nix_path_info_rows(value)?;
        if rows.is_empty() || rows.len() > MAX_CLOSURE_MEMBERS {
            bail!("recursive Nix path-info returned an invalid closure member count");
        }
        let mut members = Vec::with_capacity(rows.len());
        for (store_path, row) in rows {
            validate_store_path(&store_path)?;
            let nar_hash = row
                .get("narHash")
                .or_else(|| row.get("nar_hash"))
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("Nix path-info member omitted narHash"))?;
            let nar_hash = normalize_nar_hash(nar_hash)?;
            let nar_size_bytes = row
                .get("narSize")
                .or_else(|| row.get("nar_size"))
                .and_then(Value::as_u64)
                .filter(|value| *value > 0 && *value <= JCS_SAFE_INTEGER_MAX)
                .ok_or_else(|| anyhow::anyhow!("Nix path-info member omitted a safe narSize"))?;
            let mut references =
                row.get("references")
                    .and_then(Value::as_array)
                    .ok_or_else(|| anyhow::anyhow!("Nix path-info member omitted references"))?
                    .iter()
                    .map(|reference| {
                        reference.as_str().map(str::to_string).ok_or_else(|| {
                            anyhow::anyhow!("Nix path-info reference is not a string")
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
            references.sort();
            if references.windows(2).any(|pair| pair[0] == pair[1]) {
                bail!("Nix path-info member contains duplicate references");
            }
            members.push(SystemReleaseClosureMemberV1 {
                store_path,
                nar_hash,
                nar_size_bytes,
                references,
            });
        }
        members.sort_by(|left, right| left.store_path.cmp(&right.store_path));
        if members
            .windows(2)
            .any(|pair| pair[0].store_path == pair[1].store_path)
        {
            bail!("recursive Nix path-info returned duplicate store paths");
        }
        let manifest = Self {
            schema: SYSTEM_RELEASE_CLOSURE_SCHEMA.to_string(),
            organization_id: spec.organization_id.clone(),
            release_id: spec.release_id.clone(),
            variant_id: spec.variant_id.clone(),
            target_store_path: target_store_path.to_string(),
            members,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema != SYSTEM_RELEASE_CLOSURE_SCHEMA {
            bail!("unsupported System Release closure schema");
        }
        validate_uuid(&self.organization_id, "closure organization_id")?;
        validate_uuid(&self.release_id, "closure release_id")?;
        validate_uuid(&self.variant_id, "closure variant_id")?;
        validate_store_path(&self.target_store_path)?;
        if self.members.is_empty() || self.members.len() > MAX_CLOSURE_MEMBERS {
            bail!("System Release closure member count is invalid");
        }
        let mut by_path = BTreeMap::new();
        let mut previous: Option<&str> = None;
        let mut total = 0u64;
        for member in &self.members {
            validate_store_path(&member.store_path)?;
            validate_nar_hash(&member.nar_hash)?;
            if member.nar_size_bytes == 0
                || member.nar_size_bytes > JCS_SAFE_INTEGER_MAX
                || previous.is_some_and(|value| value >= member.store_path.as_str())
                || by_path.insert(member.store_path.as_str(), member).is_some()
            {
                bail!("System Release closure members are invalid or unsorted");
            }
            previous = Some(&member.store_path);
            total = total
                .checked_add(member.nar_size_bytes)
                .filter(|value| *value <= MAX_CLOSURE_TOTAL_BYTES)
                .ok_or_else(|| anyhow::anyhow!("System Release closure is too large"))?;
            let mut previous_reference: Option<&str> = None;
            for reference in &member.references {
                validate_store_path(reference)?;
                if previous_reference.is_some_and(|value| value >= reference.as_str()) {
                    bail!("System Release closure references are not uniquely sorted");
                }
                previous_reference = Some(reference);
            }
        }
        if !by_path.contains_key(self.target_store_path.as_str())
            || self
                .members
                .iter()
                .flat_map(|member| &member.references)
                .any(|reference| !by_path.contains_key(reference.as_str()))
        {
            bail!("System Release closure is incomplete");
        }
        let mut reachable = BTreeSet::new();
        let mut pending = vec![self.target_store_path.as_str()];
        while let Some(path) = pending.pop() {
            if !reachable.insert(path) {
                continue;
            }
            let member = by_path.get(path).ok_or_else(|| {
                anyhow::anyhow!("System Release closure reachability is incomplete")
            })?;
            pending.extend(member.references.iter().map(String::as_str));
        }
        if reachable.len() != self.members.len() {
            bail!("System Release closure contains unreachable members");
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        canonical_bytes(self, MAX_CLOSURE_BYTES)
    }

    pub fn total_nar_size_bytes(&self) -> u64 {
        self.members.iter().fold(0u64, |total, member| {
            total.saturating_add(member.nar_size_bytes)
        })
    }

    pub fn target(&self) -> Result<&SystemReleaseClosureMemberV1> {
        self.members
            .binary_search_by(|member| member.store_path.as_str().cmp(&self.target_store_path))
            .ok()
            .and_then(|index| self.members.get(index))
            .ok_or_else(|| anyhow::anyhow!("System Release closure target is missing"))
    }
}

impl SystemReleaseMarkerV3 {
    pub fn from_spec(spec: &SystemReleaseBuildSpecV3) -> Result<Self> {
        Ok(Self {
            schema: SYSTEM_RELEASE_MARKER_SCHEMA.to_string(),
            organization_id: spec.organization_id.clone(),
            release_id: spec.release_id.clone(),
            release_sequence: spec.release_sequence,
            variant_id: spec.variant_id.clone(),
            cohort_key: spec.cohort_key.clone(),
            system: spec.system.clone(),
            nixpkgs_commit: spec.nixpkgs_commit.clone(),
            baseline_version: spec.baseline_version.clone(),
            compiler_version: spec.compiler_version.clone(),
            managed_agent_version: spec.managed_agent.version.clone(),
            managed_agent_package_sha256: spec.managed_agent.package_sha256.clone(),
            managed_agent_module_sha256: spec.managed_agent.module_sha256.clone(),
            transition_helper_sha256: spec.managed_agent.transition_helper_sha256.clone(),
            watchdog_sha256: spec.managed_agent.watchdog_sha256.clone(),
            input_manifest_sha256: spec.input_manifest_sha256.clone(),
            semantic_input_sha256: spec.semantic_input_sha256.clone(),
            blueprint_compiled_module_sha256: spec.blueprint.compiled_module_sha256.clone(),
            blueprint_asset_manifest_sha256: spec.blueprint.asset_manifest_sha256.clone(),
            blueprint_extension_manifest_sha256: spec.blueprint.extension_manifest_sha256.clone(),
            compiler_runtime_module_sha256: spec.blueprint.compiler_runtime_module_sha256.clone(),
            health_policy_sha256: spec.health_policy_sha256.clone(),
            expected_state_sha256: spec.blueprint.expected_state_sha256.clone(),
        })
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        canonical_bytes(self, MAX_STRUCTURED_INPUT_BYTES)
    }

    pub fn canonical_sha256(&self) -> Result<String> {
        Ok(sha256_hex(&self.canonical_bytes()?))
    }

    fn validate(&self) -> Result<()> {
        if self.schema != SYSTEM_RELEASE_MARKER_SCHEMA
            || self.compiler_version != SYSTEM_RELEASE_COMPILER_VERSION
        {
            bail!("unsupported System Release marker identity");
        }
        validate_uuid(&self.organization_id, "marker organization_id")?;
        validate_uuid(&self.release_id, "marker release_id")?;
        validate_uuid(&self.variant_id, "marker variant_id")?;
        validate_safe_sequence(self.release_sequence, "marker release_sequence")?;
        validate_system(&self.system)?;
        validate_lower_hex(&self.nixpkgs_commit, 40, "marker nixpkgs commit")?;
        validate_bounded_token(&self.baseline_version, 1, 128, "marker baseline version")?;
        validate_bounded_token(
            &self.managed_agent_version,
            1,
            128,
            "marker managed-agent version",
        )?;
        for (label, digest) in [
            ("marker cohort", self.cohort_key.as_str()),
            (
                "marker managed-agent package",
                self.managed_agent_package_sha256.as_str(),
            ),
            (
                "marker managed-agent module",
                self.managed_agent_module_sha256.as_str(),
            ),
            (
                "marker transition helper",
                self.transition_helper_sha256.as_str(),
            ),
            ("marker watchdog", self.watchdog_sha256.as_str()),
            ("marker input manifest", self.input_manifest_sha256.as_str()),
            ("marker semantic input", self.semantic_input_sha256.as_str()),
            (
                "marker compiled Blueprint module",
                self.blueprint_compiled_module_sha256.as_str(),
            ),
            (
                "marker Blueprint asset manifest",
                self.blueprint_asset_manifest_sha256.as_str(),
            ),
            (
                "marker Blueprint extension manifest",
                self.blueprint_extension_manifest_sha256.as_str(),
            ),
            (
                "marker compiler runtime module",
                self.compiler_runtime_module_sha256.as_str(),
            ),
            ("marker health policy", self.health_policy_sha256.as_str()),
            ("marker expected state", self.expected_state_sha256.as_str()),
        ] {
            validate_sha256(digest, label)?;
        }
        Ok(())
    }
}

fn nix_path_info_rows(value: &Value) -> Result<Vec<(String, &Value)>> {
    if let Some(object) = value.as_object() {
        return Ok(object
            .iter()
            .map(|(path, row)| (path.clone(), row))
            .collect());
    }
    if let Some(array) = value.as_array() {
        return array
            .iter()
            .map(|row| {
                let path = row
                    .get("path")
                    .or_else(|| row.get("storePath"))
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow::anyhow!("Nix path-info row omitted its store path"))?;
                Ok((path.to_string(), row))
            })
            .collect();
    }
    bail!("recursive Nix path-info JSON is neither an object nor an array")
}

pub fn normalize_nar_hash(value: &str) -> Result<String> {
    if let Some(encoded) = value.strip_prefix("sha256-") {
        let decoded = STANDARD.decode(encoded).context("decode SRI NAR hash")?;
        if decoded.len() != 32 || STANDARD.encode(&decoded) != encoded {
            bail!("NAR hash is not canonical SHA-256 SRI");
        }
        return Ok(value.to_string());
    }
    let encoded = value
        .strip_prefix("sha256:")
        .ok_or_else(|| anyhow::anyhow!("NAR hash is not SHA-256"))?;
    let decoded = decode_nix_base32_sha256(encoded)?;
    Ok(format!("sha256-{}", STANDARD.encode(decoded)))
}

fn decode_nix_base32_sha256(value: &str) -> Result<[u8; 32]> {
    const ALPHABET: &[u8] = b"0123456789abcdfghijklmnpqrsvwxyz";
    if value.len() != 52 {
        bail!("Nix base32 SHA-256 digest has an invalid length");
    }
    let mut output = [0u8; 32];
    for n in 0..value.len() {
        let byte = value.as_bytes()[value.len() - n - 1];
        let digit = ALPHABET
            .iter()
            .position(|candidate| *candidate == byte)
            .ok_or_else(|| anyhow::anyhow!("Nix base32 digest contains an invalid character"))?
            as u16;
        let bit = n * 5;
        let index = bit / 8;
        let offset = bit % 8;
        if index < output.len() {
            output[index] |= (digit << offset) as u8;
        }
        if offset > 3 && index + 1 < output.len() {
            output[index + 1] |= (digit >> (8 - offset)) as u8;
        }
    }
    Ok(output)
}

pub fn initialize_attestation_key(config: &AppConfig) -> Result<()> {
    if !config.system_release.enabled {
        return Ok(());
    }
    let private_path = &config.system_release.attestation_private_key_path;
    let public_path = &config.system_release.attestation_public_key_path;
    match (private_path.exists(), public_path.exists()) {
        (true, true) => {
            load_attestation_identity(config)?;
            return Ok(());
        }
        (true, false) | (false, true) => {
            bail!("System Release attestation key pair is incomplete");
        }
        (false, false) => {}
    }
    let private_parent = private_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("attestation private key path has no parent"))?;
    let public_parent = public_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("attestation public key path has no parent"))?;
    prepare_private_directory(private_parent)?;
    if public_parent != private_parent {
        prepare_private_directory(public_parent)?;
    }
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let signing_key = SigningKey::from_bytes(&seed);
    seed.fill(0);
    let private_text = format!("{}\n", URL_SAFE_NO_PAD.encode(signing_key.to_bytes()));
    let public_text = format!(
        "{}\n",
        URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes())
    );
    atomic_write_key(private_path, private_text.as_bytes(), 0o600)?;
    if let Err(error) = atomic_write_key(public_path, public_text.as_bytes(), 0o644) {
        let _ = fs::remove_file(private_path);
        return Err(error);
    }
    sync_parent(private_path)?;
    if public_parent != private_parent {
        sync_parent(public_path)?;
    }
    load_attestation_identity(config)?;
    Ok(())
}

pub fn load_attestation_identity(config: &AppConfig) -> Result<AttestationIdentity> {
    let private_path = &config.system_release.attestation_private_key_path;
    let public_path = &config.system_release.attestation_public_key_path;
    validate_key_file(private_path, 0o600, "attestation private key")?;
    validate_key_file(public_path, 0o644, "attestation public key")?;
    let private_text = fs::read_to_string(private_path)
        .with_context(|| format!("read {}", private_path.display()))?;
    let private_text = private_text.trim_end_matches('\n');
    if private_text.trim() != private_text || private_text.contains('\n') {
        bail!("attestation private key encoding is not canonical");
    }
    let private_bytes = URL_SAFE_NO_PAD
        .decode(private_text)
        .context("decode attestation private key")?;
    let private_bytes: [u8; 32] = private_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("attestation private key has an invalid length"))?;
    if URL_SAFE_NO_PAD.encode(private_bytes) != private_text {
        bail!("attestation private key encoding is not canonical");
    }
    let signing_key = SigningKey::from_bytes(&private_bytes);
    let public_text = fs::read_to_string(public_path)
        .with_context(|| format!("read {}", public_path.display()))?;
    let public_text = public_text.trim_end_matches('\n');
    if public_text.trim() != public_text || public_text.contains('\n') {
        bail!("attestation public key encoding is not canonical");
    }
    let public_bytes = URL_SAFE_NO_PAD
        .decode(public_text)
        .context("decode attestation public key")?;
    if public_bytes.as_slice() != signing_key.verifying_key().as_bytes()
        || URL_SAFE_NO_PAD.encode(&public_bytes) != public_text
    {
        bail!("attestation public key does not match its private key");
    }
    Ok(AttestationIdentity {
        key_id: sha256_hex(&public_bytes),
        public_key: public_text.to_string(),
        signing_key,
    })
}

pub fn capability_context(config: &AppConfig) -> Result<CapabilityContext> {
    if !config.system_release.enabled
        || !config.manage.enabled
        || !config.build.enabled
        || !config.cache.enabled
    {
        bail!("System Release capability is disabled or lacks Build/Cache managed mode");
    }
    let identity = load_attestation_identity(config)?;
    let forge_node_id = managed_forge_node_id(config)?;
    crate::cache::signing_identity(config)?;
    let expected_agent = configured_managed_agent_input(config)?;
    verify_trusted_managed_agent_bundle(config, &expected_agent)?;
    let output = Command::new(&config.build.nix_binary)
        .arg("--version")
        .output()
        .with_context(|| format!("run {} --version", config.build.nix_binary))?;
    if !output.status.success() {
        bail!("configured Nix binary is unavailable");
    }
    Ok(CapabilityContext {
        forge_node_id,
        attestation_public_key: identity.public_key,
        attestation_key_id: identity.key_id,
        managed_agent: expected_agent,
    })
}

pub fn verify_trusted_managed_agent_bundle(
    config: &AppConfig,
    expected: &ManagedAgentInputV1,
) -> Result<TrustedManagedAgentBundle> {
    expected.validate()?;
    if expected != &configured_managed_agent_input(config)? {
        bail!("BuildSpec managed-agent identity does not match the operator-pinned bundle");
    }
    validate_managed_agent_config_files(config)?;
    let package_store_path = config
        .system_release
        .managed_agent_package_store_path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("managed-agent package store path is not UTF-8"))?
        .to_string();
    validate_store_path(&package_store_path)?;
    let package_sha256 = hash_nix_store_path(config, &package_store_path)?;
    let module_bytes = read_trusted_input(
        &config.system_release.managed_agent_module_path,
        4 * 1024 * 1024,
        false,
        "managed-agent module",
    )?;
    let transition_helper_bytes = read_trusted_input(
        &config.system_release.transition_helper_path,
        4 * 1024 * 1024,
        true,
        "managed-agent transition helper",
    )?;
    let watchdog_bytes = read_trusted_input(
        &config.system_release.watchdog_path,
        4 * 1024 * 1024,
        true,
        "managed-agent watchdog",
    )?;
    for (name, actual, expected) in [
        (
            "managed-agent package",
            package_sha256,
            expected.package_sha256.as_str(),
        ),
        (
            "managed-agent module",
            sha256_hex(&module_bytes),
            expected.module_sha256.as_str(),
        ),
        (
            "managed-agent transition helper",
            sha256_hex(&transition_helper_bytes),
            expected.transition_helper_sha256.as_str(),
        ),
        (
            "managed-agent watchdog",
            sha256_hex(&watchdog_bytes),
            expected.watchdog_sha256.as_str(),
        ),
    ] {
        if actual != expected {
            bail!("{name} does not match the BuildSpec digest");
        }
    }
    Ok(TrustedManagedAgentBundle {
        package_store_path,
        module_bytes,
        transition_helper_bytes,
        watchdog_bytes,
    })
}

fn configured_managed_agent_input(config: &AppConfig) -> Result<ManagedAgentInputV1> {
    let configured = ManagedAgentInputV1 {
        schema: SYSTEM_RELEASE_MANAGED_AGENT_SCHEMA.to_string(),
        version: config.system_release.managed_agent_version.clone(),
        package_sha256: config.system_release.managed_agent_package_sha256.clone(),
        module_sha256: config.system_release.managed_agent_module_sha256.clone(),
        transition_helper_sha256: config.system_release.transition_helper_sha256.clone(),
        watchdog_sha256: config.system_release.watchdog_sha256.clone(),
    };
    configured.validate()?;
    Ok(configured)
}

fn hash_nix_store_path(config: &AppConfig, path: &str) -> Result<String> {
    let output = Command::new(&config.build.nix_binary)
        .args(["hash", "path", "--type", "sha256", "--base16", path])
        .output()
        .with_context(|| format!("hash trusted managed-agent package {path}"))?;
    if !output.status.success() {
        bail!("could not hash the trusted managed-agent package");
    }
    let digest = String::from_utf8(output.stdout)
        .context("trusted managed-agent package hash is not UTF-8")?
        .trim()
        .to_ascii_lowercase();
    validate_sha256(&digest, "trusted managed-agent package hash")?;
    Ok(digest)
}

fn validate_managed_agent_config_files(config: &AppConfig) -> Result<()> {
    let package = &config.system_release.managed_agent_package_store_path;
    let package_text = package
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("managed-agent package store path is not UTF-8"))?;
    validate_store_path(package_text)?;
    let metadata = fs::metadata(package)
        .with_context(|| format!("stat managed-agent package {}", package.display()))?;
    if !metadata.is_dir() || fs::symlink_metadata(package)?.file_type().is_symlink() {
        bail!("managed-agent package must be a direct Nix store directory");
    }
    for (path, executable, label) in [
        (
            &config.system_release.managed_agent_module_path,
            false,
            "managed-agent module",
        ),
        (
            &config.system_release.transition_helper_path,
            true,
            "managed-agent transition helper",
        ),
        (
            &config.system_release.watchdog_path,
            true,
            "managed-agent watchdog",
        ),
    ] {
        validate_trusted_input_file(path, executable, label)?;
    }
    Ok(())
}

fn read_trusted_input(
    path: &Path,
    max_bytes: usize,
    executable: bool,
    label: &str,
) -> Result<Vec<u8>> {
    validate_trusted_input_file(path, executable, label)?;
    let bytes = fs::read(path).with_context(|| format!("read {label} {}", path.display()))?;
    if bytes.is_empty() || bytes.len() > max_bytes || bytes.contains(&0) {
        bail!("{label} has invalid contents or size");
    }
    Ok(bytes)
}

fn validate_trusted_input_file(path: &Path, executable: bool, label: &str) -> Result<()> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("stat {label} {}", path.display()))?;
    let mode = metadata.mode() & 0o777;
    let owner = metadata.uid();
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || (owner != 0 && owner != unsafe { libc::geteuid() })
        || mode & 0o022 != 0
        || (executable && mode & 0o100 == 0)
    {
        bail!("{label} ownership, type, or mode is unsafe");
    }
    Ok(())
}

fn managed_forge_node_id(config: &AppConfig) -> Result<String> {
    let path = &config.manage.state_path;
    validate_key_file(path, 0o600, "managed Forge state")?;
    let value: Value = serde_json::from_slice(
        &fs::read(path).with_context(|| format!("read {}", path.display()))?,
    )
    .context("parse managed Forge state")?;
    let device_id = value
        .get("device_id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("managed Forge state has no adopted device identity"))?;
    validate_bounded_token(device_id, 1, 256, "Forge node ID")?;
    Ok(device_id.to_string())
}

fn prepare_private_directory(path: &Path) -> Result<()> {
    if !path.exists() {
        fs::create_dir_all(path).with_context(|| format!("create {}", path.display()))?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("secure {}", path.display()))?;
    }
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("stat {}", path.display()))?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o777 != 0o700
    {
        bail!("attestation key directory must be owner-owned mode 0700");
    }
    Ok(())
}

fn validate_key_file(path: &Path, expected_mode: u32, label: &str) -> Result<()> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("stat {label} {}", path.display()))?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o777 != expected_mode
    {
        bail!("{label} must be an owner-owned regular file with mode {expected_mode:o}");
    }
    Ok(())
}

fn atomic_write_key(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("key path has no parent"))?;
    let name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("key path has no file name"))?
        .to_string_lossy();
    let mut random = [0u8; 8];
    OsRng.fill_bytes(&mut random);
    let temporary = parent.join(format!(
        ".{name}.{}.{}.tmp",
        std::process::id(),
        hex::encode(random)
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(mode)
            .open(&temporary)
            .with_context(|| format!("create {}", temporary.display()))?;
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        file.write_all(contents)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path).with_context(|| format!("publish {}", path.display()))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn sync_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        File::open(parent)
            .with_context(|| format!("open {}", parent.display()))?
            .sync_all()
            .with_context(|| format!("sync {}", parent.display()))?;
    }
    Ok(())
}

fn canonical_bytes<T: Serialize>(value: &T, max_bytes: usize) -> Result<Vec<u8>> {
    let value = serde_json::to_value(value).context("serialize canonical object")?;
    validate_structured_value(&value, "canonical object")?;
    let bytes = serde_json_canonicalizer::to_vec(&value).context("canonicalize JSON")?;
    if bytes.is_empty() || bytes.len() > max_bytes {
        bail!("canonical object exceeds its byte limit");
    }
    Ok(bytes)
}

fn canonical_digest_bytes<T: Serialize>(value: &T, max_bytes: usize) -> Result<Vec<u8>> {
    let value = serde_json::to_value(value).context("serialize canonical digest input")?;
    validate_structured_digest_value(&value, "canonical digest input")?;
    let bytes =
        serde_json_canonicalizer::to_vec(&value).context("canonicalize JSON digest input")?;
    if bytes.is_empty() || bytes.len() > max_bytes {
        bail!("canonical digest input exceeds its byte limit");
    }
    Ok(bytes)
}

fn canonical_sha256<T: Serialize>(value: &T, max_bytes: usize) -> Result<String> {
    Ok(sha256_hex(&canonical_bytes(value, max_bytes)?))
}

fn canonical_value_sha256(value: &Value, max_bytes: usize) -> Result<String> {
    Ok(sha256_hex(&canonical_value_bytes(value, max_bytes)?))
}

fn canonical_value_digest_sha256(value: &Value, max_bytes: usize) -> Result<String> {
    Ok(sha256_hex(&canonical_value_digest_bytes(value, max_bytes)?))
}

fn canonical_value_digest_bytes(value: &Value, max_bytes: usize) -> Result<Vec<u8>> {
    validate_structured_digest_value(value, "canonical digest value")?;
    let bytes =
        serde_json_canonicalizer::to_vec(value).context("canonicalize JSON digest value")?;
    if bytes.is_empty() || bytes.len() > max_bytes {
        bail!("canonical digest value exceeds its byte limit");
    }
    Ok(bytes)
}

fn canonical_value_bytes(value: &Value, max_bytes: usize) -> Result<Vec<u8>> {
    validate_structured_value(value, "canonical value")?;
    let bytes = serde_json_canonicalizer::to_vec(value).context("canonicalize JSON value")?;
    if bytes.is_empty() || bytes.len() > max_bytes {
        bail!("canonical value exceeds its byte limit");
    }
    Ok(bytes)
}

fn validate_structured_value(value: &Value, label: &str) -> Result<()> {
    fn walk(value: &Value, depth: usize, nodes: &mut usize, label: &str) -> Result<()> {
        if depth > MAX_VALUE_DEPTH {
            bail!("{label} is too deeply nested");
        }
        *nodes = nodes.saturating_add(1);
        if *nodes > MAX_VALUE_NODES {
            bail!("{label} has too many values");
        }
        match value {
            Value::Null | Value::Bool(_) => {}
            Value::Number(number) => {
                let valid = number
                    .as_u64()
                    .is_some_and(|value| value <= JCS_SAFE_INTEGER_MAX)
                    || number
                        .as_i64()
                        .is_some_and(|value| value.unsigned_abs() <= JCS_SAFE_INTEGER_MAX);
                if !valid {
                    bail!("{label} contains a float or unsafe integer");
                }
            }
            Value::String(text) => validate_bounded_text(text, 0, MAX_STRING_BYTES, label)?,
            Value::Array(values) => {
                for value in values {
                    walk(value, depth + 1, nodes, label)?;
                }
            }
            Value::Object(values) => {
                for (key, value) in values {
                    validate_bounded_text(key, 1, 256, label)?;
                    walk(value, depth + 1, nodes, label)?;
                }
            }
        }
        Ok(())
    }

    walk(value, 0, &mut 0, label)
}

fn validate_structured_digest_value(value: &Value, label: &str) -> Result<()> {
    fn walk(value: &Value, depth: usize, nodes: &mut usize, label: &str) -> Result<()> {
        if depth > MAX_VALUE_DEPTH {
            bail!("{label} is too deeply nested");
        }
        *nodes = nodes.saturating_add(1);
        if *nodes > MAX_VALUE_NODES {
            bail!("{label} has too many values");
        }
        match value {
            Value::Null | Value::Bool(_) => {}
            Value::Number(number) => {
                let valid = number
                    .as_u64()
                    .is_some_and(|value| value <= JCS_SAFE_INTEGER_MAX)
                    || number
                        .as_i64()
                        .is_some_and(|value| value.unsigned_abs() <= JCS_SAFE_INTEGER_MAX);
                if !valid {
                    bail!("{label} contains a float or unsafe integer");
                }
            }
            Value::String(text) => {
                if text.len() > MAX_STRING_BYTES
                    || text.chars().any(|character| {
                        character == '\0'
                            || (character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
                    })
                {
                    bail!("{label} contains an invalid string");
                }
            }
            Value::Array(values) => {
                for value in values {
                    walk(value, depth + 1, nodes, label)?;
                }
            }
            Value::Object(values) => {
                for (key, value) in values {
                    validate_bounded_text(key, 1, 256, label)?;
                    walk(value, depth + 1, nodes, label)?;
                }
            }
        }
        Ok(())
    }

    walk(value, 0, &mut 0, label)
}

fn validate_blueprint_render_allowlist(config: &Value) -> Result<()> {
    system_release_compiler_v3::validate_projection(config)
        .map(|_| ())
        .map_err(anyhow::Error::msg)
}

fn render_blueprint_materials(
    blueprint: &SystemReleaseBlueprintInputV3,
    materials: &SystemReleaseMaterialBundle,
) -> Result<(Vec<u8>, Vec<RenderedSystemReleaseFile>)> {
    let assets = blueprint
        .asset_manifest
        .get("assets")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("Blueprint asset manifest omits assets"))?;
    let expected: BTreeSet<String> = assets
        .iter()
        .filter_map(|asset| asset.get("sha256").and_then(Value::as_str))
        .map(str::to_string)
        .collect();
    if assets
        .iter()
        .any(|asset| asset.get("sha256").and_then(Value::as_str).is_none())
        || materials.assets.keys().cloned().collect::<BTreeSet<_>>() != expected
    {
        bail!("downloaded Blueprint assets do not exactly match the BuildSpec manifest");
    }
    let mut system_entries = Vec::new();
    let mut home_entries = Vec::new();
    let mut directory_entries = Vec::new();
    let mut has_captured_dconf = false;
    let mut files = Vec::with_capacity(assets.len());
    for asset in assets {
        let sha256 = asset
            .get("sha256")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("Blueprint asset digest is missing"))?;
        let size_bytes = asset
            .get("size_bytes")
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow::anyhow!("Blueprint asset size is missing"))?;
        let target_scope = asset
            .get("target_scope")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("Blueprint asset target scope is missing"))?;
        let target_path = asset
            .get("target_path")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("Blueprint asset target path is missing"))?;
        let application_mode = asset
            .get("application_mode")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("Blueprint asset application mode is missing"))?;
        let bytes = materials
            .assets
            .get(sha256)
            .ok_or_else(|| anyhow::anyhow!("Blueprint asset bytes are missing"))?;
        if bytes.len() as u64 != size_bytes || sha256_hex(bytes) != sha256 {
            bail!("downloaded Blueprint asset fails its content-addressed identity");
        }
        let file_name = format!("asset-{sha256}");
        files.push(rendered_file(file_name.clone(), bytes.clone(), 0o600));
        if asset.get("logical_path").and_then(Value::as_str) == Some("desktop/dconf.ini") {
            has_captured_dconf = true;
            system_entries.push(format!(
                "    {{ source = ./{file_name}; target = \"dconf/db/cybex.d/00-cybex-captured\"; }}"
            ));
        }
        if asset.get("logical_path").and_then(Value::as_str) == Some("home/directory-manifest.json")
        {
            let manifest: Value = serde_json::from_slice(bytes)
                .context("captured directory manifest is invalid JSON")?;
            let owner = target_path
                .strip_prefix("/home/")
                .and_then(|value| value.split('/').next())
                .filter(|value| !value.is_empty())
                .ok_or_else(|| anyhow::anyhow!("captured directory owner is missing"))?;
            let directories = manifest
                .get("directories")
                .and_then(Value::as_array)
                .ok_or_else(|| anyhow::anyhow!("captured directory manifest omits directories"))?;
            if directories.len() > 2048 {
                bail!("captured directory manifest exceeds its entry bound");
            }
            for directory in directories {
                let relative = directory
                    .as_str()
                    .filter(|value| valid_captured_relative_path(value))
                    .ok_or_else(|| anyhow::anyhow!("captured directory path is unsafe"))?;
                directory_entries.push(format!(
                    "    {{ target = {}; owner = {}; }}",
                    nix_string(&format!("/home/{owner}/{relative}")),
                    nix_string(owner)
                ));
            }
        }
        match target_scope {
            "system" => {
                let etc_path = target_path
                    .strip_prefix("/etc/")
                    .ok_or_else(|| anyhow::anyhow!("system Blueprint asset target is unsafe"))?;
                system_entries.push(format!(
                    "    {{ source = ./{file_name}; target = {}; }}",
                    nix_string(etc_path)
                ));
            }
            "captured_user" => {
                let remainder = target_path
                    .strip_prefix("/home/")
                    .ok_or_else(|| anyhow::anyhow!("home Blueprint asset target is unsafe"))?;
                let owner = remainder
                    .split('/')
                    .next()
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| anyhow::anyhow!("home Blueprint asset owner is missing"))?;
                home_entries.push(format!(
                    "    {{ source = ./{file_name}; target = {}; owner = {}; mode = {}; }}",
                    nix_string(target_path),
                    nix_string(owner),
                    nix_string(application_mode)
                ));
            }
            _ => bail!("Blueprint asset target scope is unsupported"),
        }
    }
    let module = format!(
        r#"{{ lib, pkgs, ... }}:
let
  systemAssets = [
{system_entries}
  ];
  homeAssets = [
{home_entries}
  ];
  homeDirectories = [
{directory_entries}
  ];
  hasCapturedDconf = {has_captured_dconf};
in
{{
  environment.etc = builtins.listToAttrs (map (asset: {{
    name = asset.target;
    value = {{ source = asset.source; mode = "0644"; }};
  }}) systemAssets);

  programs.dconf.enable = lib.mkIf hasCapturedDconf true;
  environment.etc."dconf/profile/user" = lib.mkIf hasCapturedDconf {{
    text = "user-db:user\nsystem-db:cybex\n";
  }};
  system.activationScripts.cybexBlueprintDconf = lib.mkIf hasCapturedDconf {{
    deps = [ "etc" ];
    text = "${{pkgs.dconf}}/bin/dconf update";
  }};

  system.activationScripts.cybexBlueprintAssets = lib.mkIf (homeAssets != [] || homeDirectories != []) {{
    deps = [ "users" ];
    text = (lib.concatMapStringsSep "\n" (directory:
      let
        target = lib.escapeShellArg directory.target;
        owner = lib.escapeShellArg directory.owner;
      in "${{pkgs.coreutils}}/bin/install -d -m 0700 -o " + owner + " -g users " + target
    ) homeDirectories) + "\n" + (lib.concatMapStringsSep "\n" (asset:
      let
        source = lib.escapeShellArg (toString asset.source);
        target = lib.escapeShellArg asset.target;
        owner = lib.escapeShellArg asset.owner;
        install = "${{pkgs.coreutils}}/bin/install -D -m 0644 -o " + owner
          + " -g users " + source + " " + target;
      in if asset.mode == "seed_once" || asset.mode == "managed_default"
         then "if [ ! -e " + target + " ]; then " + install + "; fi"
         else install
    ) homeAssets);
  }};
}}
"#,
        system_entries = system_entries.join("\n"),
        home_entries = home_entries.join("\n"),
        directory_entries = directory_entries.join("\n"),
        has_captured_dconf = if has_captured_dconf { "true" } else { "false" },
    );
    Ok((module.into_bytes(), files))
}

fn valid_captured_relative_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 4096
        && !value.starts_with('/')
        && !value.ends_with('/')
        && !value.contains("//")
        && !value.contains('\\')
        && !value.chars().any(char::is_control)
        && value
            .split('/')
            .all(|component| !component.is_empty() && !matches!(component, "." | ".."))
}

fn render_blueprint_extensions(
    blueprint: &SystemReleaseBlueprintInputV3,
    materials: &SystemReleaseMaterialBundle,
) -> Result<(Vec<u8>, Vec<RenderedSystemReleaseFile>)> {
    let modules = blueprint
        .extension_manifest
        .get("modules")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("Blueprint extension manifest omits modules"))?;
    let expected: BTreeSet<String> = modules
        .iter()
        .filter_map(|module| module.get("sha256").and_then(Value::as_str))
        .map(str::to_string)
        .collect();
    if modules
        .iter()
        .any(|module| module.get("sha256").and_then(Value::as_str).is_none())
        || materials
            .extensions
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>()
            != expected
    {
        bail!("downloaded Blueprint extensions do not exactly match the BuildSpec manifest");
    }
    let mut imports = Vec::with_capacity(modules.len());
    let mut parameters_by_id = serde_json::Map::new();
    let mut parameters_by_name = serde_json::Map::new();
    let mut parameters_by_name_version = serde_json::Map::new();
    let mut seen_names = BTreeSet::new();
    let mut seen_name_versions = BTreeSet::new();
    let mut files = Vec::with_capacity(modules.len());
    for module in modules {
        let id = module
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("Blueprint extension ID is missing"))?;
        let name = module
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("Blueprint extension name is missing"))?;
        let version = module
            .get("version")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("Blueprint extension version is missing"))?;
        let name_version = format!("{name}@{version}");
        if !seen_names.insert(name.to_string()) || !seen_name_versions.insert(name_version.clone())
        {
            bail!("Blueprint extension name is duplicated");
        }
        let sha256 = module
            .get("sha256")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("Blueprint extension digest is missing"))?;
        let size_bytes = module
            .get("size_bytes")
            .and_then(Value::as_u64)
            .ok_or_else(|| anyhow::anyhow!("Blueprint extension size is missing"))?;
        let source = materials
            .extensions
            .get(sha256)
            .ok_or_else(|| anyhow::anyhow!("Blueprint extension bytes are missing"))?;
        if source.len() as u64 != size_bytes || sha256_hex(source) != sha256 {
            bail!("downloaded Blueprint extension fails its content-addressed identity");
        }
        validate_governed_extension_source(source)?;
        imports.push(format!("    ./extension-{sha256}.nix"));
        files.push(rendered_file(
            format!("extension-{sha256}.nix"),
            source.clone(),
            0o600,
        ));
        let module_parameters = module
            .get("parameters")
            .cloned()
            .unwrap_or_else(|| json!({}));
        parameters_by_id.insert(id.to_string(), module_parameters.clone());
        parameters_by_name.insert(name.to_string(), module_parameters.clone());
        parameters_by_name_version.insert(name_version, module_parameters);
    }
    let parameters_json = serde_json::to_string(&json!({
        "byId": parameters_by_id,
        "byName": parameters_by_name,
        "byNameVersion": parameters_by_name_version,
    }))?;
    let module = format!(
        r#"{{ ... }}:
{{
  imports = [
{imports}
  ];
  _module.args.cybexBlueprintExtensionParameters = builtins.fromJSON {parameters};
}}
"#,
        imports = imports.join("\n"),
        parameters = nix_string(&parameters_json),
    )
    .into_bytes();
    Ok((module, files))
}

fn validate_governed_extension_source(source: &[u8]) -> Result<()> {
    if source.is_empty() || source.len() > 1024 * 1024 || source.contains(&0) {
        bail!("governed Blueprint extension source is empty or oversized");
    }
    let source = std::str::from_utf8(source).context("Blueprint extension source is not UTF-8")?;
    if source
        .chars()
        .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    {
        bail!("governed Blueprint extension source contains invalid control characters");
    }
    let lower = source.to_ascii_lowercase();
    for forbidden in [
        "builtins.fetch",
        "builtins.getenv",
        "fetchurl",
        "fetchgit",
        "fetchfromgithub",
        "http://",
        "https://",
        "<nixpkgs",
        "/run/secrets",
        "/etc/shadow",
        "-----begin private key-----",
    ] {
        if lower.contains(forbidden) {
            bail!("governed Blueprint extension contains forbidden external or secret material");
        }
    }
    Ok(())
}

fn nix_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('"');
    let mut chars = value.chars().peekable();
    while let Some(character) = chars.next() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            '$' if chars.peek() == Some(&'{') => escaped.push_str("\\$"),
            _ => escaped.push(character),
        }
    }
    escaped.push('"');
    escaped
}

fn validate_renderer_keys(
    object: &serde_json::Map<String, Value>,
    allowed: &[&str],
    label: &str,
) -> Result<()> {
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        bail!("{label} contains a key outside the compiler-v3 contract");
    }
    Ok(())
}

fn validate_uuid(value: &str, label: &str) -> Result<Uuid> {
    let parsed = Uuid::parse_str(value).with_context(|| format!("{label} is not a UUID"))?;
    if parsed.is_nil() || parsed.to_string() != value {
        bail!("{label} is not a canonical non-nil UUID");
    }
    Ok(parsed)
}

fn validate_system(value: &str) -> Result<()> {
    if !matches!(value, "x86_64-linux" | "aarch64-linux") {
        bail!("unsupported System Release Nix system");
    }
    Ok(())
}

fn validate_safe_sequence(value: u64, label: &str) -> Result<()> {
    if value == 0 || value > JCS_SAFE_INTEGER_MAX {
        bail!("{label} is outside the safe sequence range");
    }
    Ok(())
}

fn validate_sha256(value: &str, label: &str) -> Result<()> {
    validate_lower_hex(value, 64, label)
}

fn validate_lower_hex(value: &str, size: usize, label: &str) -> Result<()> {
    if value.len() != size
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("{label} must be canonical lowercase hexadecimal");
    }
    Ok(())
}

fn validate_bounded_text(value: &str, min: usize, max: usize, label: &str) -> Result<()> {
    if value.len() < min
        || value.len() > max
        || value.chars().any(|character| character.is_control())
    {
        bail!("{label} is invalid or outside its byte limit");
    }
    Ok(())
}

fn validate_bounded_token(value: &str, min: usize, max: usize, label: &str) -> Result<()> {
    validate_bounded_text(value, min, max, label)?;
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'+' | b'-')
    }) {
        bail!("{label} contains unsupported characters");
    }
    Ok(())
}

fn valid_managed_baseline_uuid_device(value: &str) -> bool {
    let Some(suffix) = value.strip_prefix("/dev/disk/by-uuid/") else {
        return false;
    };
    Uuid::parse_str(suffix)
        .ok()
        .is_some_and(|uuid| uuid.hyphenated().to_string() == suffix)
}

fn valid_managed_baseline_label_device(value: &str) -> bool {
    value
        .strip_prefix("/dev/disk/by-label/")
        .is_some_and(|suffix| {
            (1..=64).contains(&suffix.len())
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._+-".contains(&byte))
        })
}

fn valid_managed_baseline_whole_disk(value: &str) -> bool {
    value
        .strip_prefix("/dev/disk/by-id/")
        .is_some_and(|suffix| {
            (1..=240).contains(&suffix.len())
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._:+-".contains(&byte))
        })
}

fn valid_managed_baseline_mapper_device(value: &str) -> bool {
    value.strip_prefix("/dev/mapper/").is_some_and(|suffix| {
        (1..=64).contains(&suffix.len())
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    })
}

const SYSTEM_RELEASE_MANAGED_MODULE_ALLOWLIST: &[&str] = &[
    "aacraid",
    "ahci",
    "amdgpu",
    "ata_piix",
    "btrfs",
    "cryptd",
    "dm_crypt",
    "dm_mod",
    "ehci_hcd",
    "ehci_pci",
    "ext4",
    "f2fs",
    "hid_hyperv",
    "hpsa",
    "hv_netvsc",
    "hv_storvsc",
    "hv_vmbus",
    "hyperv_fb",
    "hyperv_keyboard",
    "i915",
    "isci",
    "kvm",
    "kvm-amd",
    "kvm-intel",
    "megaraid_sas",
    "mmc_block",
    "mpt3sas",
    "mptspi",
    "nouveau",
    "nvme",
    "nvidia",
    "nvidia_drm",
    "nvidia_modeset",
    "nvidia_uvm",
    "ohci_hcd",
    "ohci_pci",
    "pata_acpi",
    "rtsx_pci_sdmmc",
    "scsi_mod",
    "sd_mod",
    "sdhci_pci",
    "sr_mod",
    "uas",
    "uhci_hcd",
    "usb_storage",
    "usbhid",
    "vboxguest",
    "vboxsf",
    "vboxvideo",
    "virtio_balloon",
    "virtio_blk",
    "virtio_console",
    "virtio_gpu",
    "virtio_net",
    "virtio_pci",
    "virtio_rng",
    "virtio_scsi",
    "vmw_pvscsi",
    "vmwgfx",
    "vmxnet3",
    "xfs",
    "xhci_hcd",
    "xhci_pci",
];

fn valid_managed_baseline_module(value: &str) -> bool {
    SYSTEM_RELEASE_MANAGED_MODULE_ALLOWLIST.contains(&value)
}

fn valid_managed_baseline_root_option(value: &str, fs_type: &str) -> bool {
    matches!(value, "defaults" | "discard" | "noatime")
        || (fs_type == "btrfs"
            && (matches!(value, "discard=async" | "subvol=@" | "subvol=@root")
                || value
                    .strip_prefix("compress=zstd:")
                    .and_then(|level| level.parse::<u8>().ok())
                    .is_some_and(|level| (1..=19).contains(&level))))
}

fn valid_managed_baseline_efi_option(value: &str) -> bool {
    matches!(
        value,
        "defaults" | "noatime" | "dmask=0077" | "fmask=0077" | "umask=0077"
    )
}

fn validate_sorted_unique_baseline_values(
    values: &[String],
    maximum: usize,
    label: &str,
) -> Result<()> {
    if values.len() > maximum
        || values.windows(2).any(|pair| {
            pair.first()
                .zip(pair.get(1))
                .is_some_and(|(left, right)| left >= right)
        })
    {
        bail!("{label} is not bounded and uniquely sorted");
    }
    Ok(())
}

fn validate_sorted_unique_tokens(values: &[String], max: usize, label: &str) -> Result<()> {
    if values.len() > max {
        bail!("{label} contains too many entries");
    }
    let mut previous: Option<&str> = None;
    for value in values {
        validate_bounded_token(value, 1, 256, label)?;
        if previous.is_some_and(|previous| previous >= value.as_str()) {
            bail!("{label} is not uniquely sorted");
        }
        previous = Some(value);
    }
    Ok(())
}

fn validate_systemd_unit(value: &str) -> Result<()> {
    validate_bounded_token(value, 3, 256, "systemd unit")?;
    if !value.ends_with(".service") {
        bail!("health policy systemd unit must be a service unit");
    }
    Ok(())
}

pub(crate) fn validate_store_path(value: &str) -> Result<()> {
    let Some(rest) = value.strip_prefix("/nix/store/") else {
        bail!("Forge provenance target is not a Nix store path");
    };
    let Some((hash, name)) = rest.split_once('-') else {
        bail!("Forge provenance target is not a Nix store path");
    };
    const NIX_BASE32: &str = "0123456789abcdfghijklmnpqrsvwxyz";
    if value.len() > 4096
        || hash.len() != 32
        || name.is_empty()
        || !hash.chars().all(|character| NIX_BASE32.contains(character))
        || !name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.' | b'_' | b'?' | b'=')
        })
    {
        bail!("Forge provenance target is not a canonical Nix store path");
    }
    Ok(())
}

fn validate_nar_hash(value: &str) -> Result<()> {
    let Some(encoded) = value.strip_prefix("sha256-") else {
        bail!("Forge provenance NAR hash is invalid");
    };
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .context("decode Forge provenance NAR hash")?;
    if bytes.len() != 32 || base64::engine::general_purpose::STANDARD.encode(bytes) != encoded {
        bail!("Forge provenance NAR hash is not canonical");
    }
    Ok(())
}

fn parse_canonical_time(value: &str) -> Result<DateTime<Utc>> {
    let parsed = DateTime::parse_from_rfc3339(value)
        .context("parse canonical System Release timestamp")?
        .with_timezone(&Utc);
    if parsed.to_rfc3339_opts(SecondsFormat::Secs, true) != value {
        bail!("System Release timestamp is not canonical UTC seconds");
    }
    Ok(parsed)
}

fn signing_message(domain: &str, organization_id: Uuid, canonical: &[u8]) -> Result<Vec<u8>> {
    if canonical.is_empty() || canonical.len() > MAX_STRUCTURED_INPUT_BYTES {
        bail!("signed provenance canonical bytes are invalid");
    }
    Ok(format!(
        "CYBEX-SIGNED-OBJECT-V1\n{domain}\n{organization_id}\n{}\n",
        sha256_hex(canonical)
    )
    .into_bytes())
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::time::{SystemTime, UNIX_EPOCH};

    const TEST_COMPILED_BLUEPRINT_MODULE_NIX: &str =
        include_str!("system_release_blueprint_v3.nix");

    fn test_temp_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "cybex-forge-system-release-{label}-{}-{nanos}",
            std::process::id()
        ))
    }

    fn standard_source_config() -> Value {
        serde_json::from_str(include_str!(
            "../protocol/system-release-compiler-v3-standard-source.json"
        ))
        .expect("shared Standard compiler-v3 source golden")
    }

    fn supported_system_release_nixpkgs_pin() -> Value {
        let fixture: Value = serde_json::from_str(include_str!(
            "../protocol/system-release-supported-nixpkgs-pin.json"
        ))
        .expect("shared supported System Release nixpkgs pin fixture");
        assert_eq!(
            fixture["schema"],
            "cybex.system-release-supported-nixpkgs-pin-fixture.v1"
        );
        assert_eq!(fixture["pin"]["nixos_release"], "26.05");
        assert_eq!(fixture["pin"]["channel"], "nixos-26.05");
        assert_eq!(
            fixture["pin"]["source_url"],
            "https://channels.nixos.org/nixos-26.05"
        );
        let commit = fixture["pin"]["nixpkgs_commit"].as_str().unwrap();
        assert_eq!(commit.len(), 40);
        assert!(
            commit
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
        fixture
    }

    fn supported_system_release_nixpkgs_flake() -> String {
        let fixture = supported_system_release_nixpkgs_pin();
        format!(
            "github:NixOS/nixpkgs/{}",
            fixture["pin"]["nixpkgs_commit"].as_str().unwrap()
        )
    }

    #[allow(dead_code)]
    fn standard_source_config_inline() -> Value {
        let setting = |value: &str| json!({"value": value});
        let applications = [
            ("Cybex Agent", "cybex-agent", "ph-shield-check"),
            ("Firefox ESR", "firefox-esr", "ph-globe"),
            ("Dolphin", "kdePackages.dolphin", "ph-folder-open"),
            ("Konsole", "kdePackages.konsole", "ph-terminal-window"),
            (
                "System Settings",
                "kdePackages.systemsettings",
                "ph-sliders-horizontal",
            ),
            ("Spectacle", "kdePackages.spectacle", "ph-camera"),
            ("LibreOffice", "libreoffice", "ph-file-text"),
            ("Thunderbird", "thunderbird", "ph-envelope-simple"),
        ]
        .into_iter()
        .enumerate()
        .map(|(index, (label, package_ref, icon))| {
            json!({
                "id": format!("exp-app-{index}"),
                "label": label,
                "package_ref": package_ref,
                "package_source": "nixpkgs",
                "meta": format!("nixpkgs · {package_ref}"),
                "icon": icon,
                "source": "Blueprint",
            })
        })
        .collect::<Vec<_>>();
        json!({
            "local_account_profile_selection_mode": "explicit",
            "settings": {
                "network": {
                    "manager": setting("NetworkManager"),
                    "dns": setting("1.1.1.1, 1.0.0.1"),
                },
                "desktop": {
                    "profile": setting("Taskbar"),
                    "de": setting("KDE Plasma"),
                    "greeter": setting("SDDM (Wayland)"),
                    "layout": setting("Taskbar"),
                    "overview": setting("Application launcher, task switcher, and visible system tray"),
                    "panel": setting("Bottom taskbar with launcher, pinned apps, tray, and clock"),
                    "terminal": setting("Konsole"),
                    "screenshots": setting("Spectacle"),
                    "portal": setting("KDE portal"),
                    "login": setting("Greeter - no autologin"),
                    "browser": setting("Firefox ESR"),
                    "theme": setting("Cybex Graphite"),
                    "icons": setting("Papirus Dark"),
                    "cursor": setting("Bibata Modern Ice"),
                    "wallpaper": setting("Cybex Graphite Ribbon"),
                    "dock": setting("Files · Browser · Mail · Settings · Terminal · Screenshot"),
                    "audio": setting("PipeWire + WirePlumber"),
                    "bluetooth": setting("Enabled"),
                    "language": setting("en-US"),
                    "keyboard": setting("US"),
                    "timezone": setting("UTC"),
                },
                "security": {
                    "encryption": setting("LUKS2 - required"),
                    "firewall": setting("nftables - default-deny inbound"),
                    "screenlock": setting("10 min"),
                    "sudo": setting("No local admin"),
                    "usb": setting("Read-only"),
                },
                "updates": {
                    "oschannel": setting("nixpkgs 26.05 stable"),
                    "cadence": setting("Weekly"),
                    "window": setting("Off-hours"),
                    "rollback": setting("Keep previous generations for rollback"),
                },
                "printing": {"printervis": setting("Show assigned only")},
                "monitoring": {"logs": setting("errors + audit")},
            },
            "lists": {
                "apps": {
                    "installed": {
                        "title": "Installed applications",
                        "icon": "ph-app-window",
                        "items": applications,
                    }
                }
            }
        })
    }

    fn fixture() -> SystemReleaseBuildSpecV3 {
        let source_config = standard_source_config();
        let mut config = system_release_compiler_v3::derive_projection(&source_config)
            .unwrap()
            .into_wire();
        let source_expected_state_sha256 = "d".repeat(64);
        let expected_state = json!({
            "schema": SYSTEM_RELEASE_EXPECTED_STATE_PROJECTION_SCHEMA,
            "compiler_revision": SYSTEM_RELEASE_EXPECTED_STATE_PROJECTION_REVISION,
            "source_expected_state_sha256": source_expected_state_sha256,
            "checks": [
                {"id": "desktop.browser", "kind": "kconfig-value", "expected": {
                    "file": "/etc/xdg/kdeglobals", "section": "General",
                    "key": "BrowserApplication", "value": "firefox-esr.desktop"
                }},
                {"id": "desktop.terminal", "kind": "kconfig-value", "expected": {
                    "file": "/etc/xdg/kdeglobals", "section": "General",
                    "key": "TerminalApplication", "value": "konsole"
                }},
                {"id": "identity.fallback", "kind": "local-user-presence", "expected": {
                    "username": "cybex-admin", "present": true
                }},
                {"id": "network.dns", "kind": "dns-resolvers-exclusive", "expected": {
                    "resolvers": ["1.0.0.1", "1.1.1.1"]
                }}
            ]
        });
        // Keep fixture ownership explicit so mutations cannot accidentally share values.
        let config_sha256 = canonical_value_sha256(&config, MAX_STRUCTURED_INPUT_BYTES).unwrap();
        let asset_manifest = config["asset_manifest"].clone();
        let asset_manifest_sha256 = config["asset_manifest_sha256"]
            .as_str()
            .unwrap()
            .to_string();
        let extension_manifest = config["extension_manifest"].clone();
        let extension_manifest_sha256 = config["extension_manifest_sha256"]
            .as_str()
            .unwrap()
            .to_string();
        let expected_state_sha256 =
            canonical_value_sha256(&expected_state, MAX_STRUCTURED_INPUT_BYTES).unwrap();
        let baseline = ManagedBaselineV1 {
            schema: SYSTEM_RELEASE_BASELINE_SCHEMA.into(),
            version: SYSTEM_RELEASE_BASELINE_VERSION.into(),
            system: "x86_64-linux".into(),
            state_version: "26.05".into(),
            disk_layout_profile: ManagedDiskLayoutProfile::SingleDiskGptUefi,
            boot_mode: ManagedBootMode::Uefi,
            bootloader: ManagedBootloader::Grub,
            bootloader_device: None,
            root_encryption: ManagedRootEncryptionV1 {
                mode: ManagedRootEncryptionMode::Luks2,
                mapper_name: Some("cybex-root".into()),
                underlying_device: Some("/dev/disk/by-partlabel/CYBEX-NIXOS".into()),
            },
            root_file_system: ManagedFileSystemV1 {
                mount_point: "/".into(),
                device: "/dev/mapper/cybex-root".into(),
                fs_type: "ext4".into(),
                options: vec!["noatime".into()],
            },
            efi_file_system: Some(ManagedFileSystemV1 {
                mount_point: "/boot".into(),
                device: "/dev/disk/by-label/CYBEX-EFI".into(),
                fs_type: "vfat".into(),
                options: vec!["fmask=0077".into()],
            }),
            swap_devices: Vec::new(),
            initrd_available_kernel_modules: vec!["ahci".into(), "xhci_pci".into()],
            initrd_kernel_modules: Vec::new(),
            kernel_modules: vec!["kvm-intel".into()],
            hardware_profile: ManagedHardwareProfileV1 {
                cpu_architecture: "x86_64".into(),
                virtualization: "kvm".into(),
                graphics_policy: "open_graphics".into(),
                firmware: "redistributable".into(),
            },
            transition_protocol: SYSTEM_RELEASE_TRANSITION_PROTOCOL.into(),
            watchdog_protocol: SYSTEM_RELEASE_WATCHDOG_PROTOCOL.into(),
        };
        let health_policy = SystemReleaseHealthPolicyV1 {
            schema: SYSTEM_RELEASE_HEALTH_POLICY_SCHEMA.into(),
            revision: "baseline-v1".into(),
            required_checks: vec![
                SystemReleaseHealthCheckPolicyV1 {
                    check_id: "active_store".into(),
                    kind: SystemReleaseHealthCheckKind::ActiveStorePath,
                    unit: None,
                },
                SystemReleaseHealthCheckPolicyV1 {
                    check_id: "agent_reconnected".into(),
                    kind: SystemReleaseHealthCheckKind::AgentReconnected,
                    unit: None,
                },
                SystemReleaseHealthCheckPolicyV1 {
                    check_id: "boot_default".into(),
                    kind: SystemReleaseHealthCheckKind::BootDefaultPath,
                    unit: None,
                },
                SystemReleaseHealthCheckPolicyV1 {
                    check_id: "expected_state".into(),
                    kind: SystemReleaseHealthCheckKind::ExpectedState,
                    unit: None,
                },
                SystemReleaseHealthCheckPolicyV1 {
                    check_id: "manage_report".into(),
                    kind: SystemReleaseHealthCheckKind::ManageAcceptedReport,
                    unit: None,
                },
                SystemReleaseHealthCheckPolicyV1 {
                    check_id: "profile_store".into(),
                    kind: SystemReleaseHealthCheckKind::SystemProfilePath,
                    unit: None,
                },
            ],
            reconnect_timeout_seconds: 120,
            watchdog_timeout_seconds: 300,
        };
        let baseline_sha256 = canonical_sha256(&baseline, MAX_STRUCTURED_INPUT_BYTES).unwrap();
        let health_policy_sha256 =
            canonical_sha256(&health_policy, MAX_STRUCTURED_INPUT_BYTES).unwrap();
        let input_manifest_sha256 = "a".repeat(64);
        let compiled_module_nix = TEST_COMPILED_BLUEPRINT_MODULE_NIX;
        let compiler_runtime_module_nix = SYSTEM_RELEASE_COMPILER_RUNTIME_MODULE_NIX;
        let mut spec = SystemReleaseBuildSpecV3 {
            schema_version: 3,
            kind: SYSTEM_RELEASE_BUILD_KIND.into(),
            artifact_type: SYSTEM_RELEASE_ARTIFACT_TYPE.into(),
            target: SYSTEM_RELEASE_BUILD_TARGET.into(),
            system: "x86_64-linux".into(),
            input_revision: "018f6b61-a646-7f7c-a651-7ee13ad42f85:1".into(),
            input_config_hash: input_manifest_sha256.clone(),
            organization_id: "018f6b61-a646-7f7c-a651-7ee13ad42f84".into(),
            release_id: "018f6b61-a646-7f7c-a651-7ee13ad42f85".into(),
            release_sequence: 1,
            variant_id: "018f6b61-a646-7f7c-a651-7ee13ad42f88".into(),
            forge_artifact_id: "018f6b61-a646-7f7c-a651-7ee13ad42f91".into(),
            cohort_key: baseline_sha256.clone(),
            baseline_version: baseline.version.clone(),
            compiler_version: SYSTEM_RELEASE_COMPILER_VERSION.into(),
            nixpkgs_commit: "b".repeat(40),
            input_manifest_sha256,
            semantic_input_sha256: "0".repeat(64),
            blueprint: SystemReleaseBlueprintInputV3 {
                schema: SYSTEM_RELEASE_BLUEPRINT_INPUT_SCHEMA.into(),
                blueprint_id: "018f6b61-a646-7f7c-a651-7ee13ad42f86".into(),
                blueprint_revision_id: "018f6b61-a646-7f7c-a651-7ee13ad42f87".into(),
                policy_revision_id: "018f6b61-a646-7f7c-a651-7ee13ad42f89".into(),
                name: "Managed Workstation".into(),
                config_schema: SYSTEM_RELEASE_BLUEPRINT_PROJECTION_SCHEMA.into(),
                config: std::mem::take(&mut config),
                config_sha256,
                source_config_sha256: system_release_compiler_v3::canonical_json_sha256(
                    &source_config,
                )
                .unwrap(),
                compiled_module_sha256: sha256_hex(compiled_module_nix.as_bytes()),
                asset_manifest,
                asset_manifest_sha256,
                extension_manifest,
                extension_manifest_sha256,
                compiler_runtime_module_sha256: sha256_hex(compiler_runtime_module_nix.as_bytes()),
                source_expected_state_sha256,
                expected_state_schema: SYSTEM_RELEASE_EXPECTED_STATE_PROJECTION_SCHEMA.into(),
                expected_state,
                expected_state_sha256,
            },
            managed_baseline: baseline,
            managed_baseline_sha256: baseline_sha256,
            managed_agent: ManagedAgentInputV1 {
                schema: SYSTEM_RELEASE_MANAGED_AGENT_SCHEMA.into(),
                version: "0.1.0".into(),
                package_sha256: "1".repeat(64),
                module_sha256: "2".repeat(64),
                transition_helper_sha256: "3".repeat(64),
                watchdog_sha256: "4".repeat(64),
            },
            health_policy,
            health_policy_sha256,
        };
        spec.semantic_input_sha256 = spec.computed_semantic_input_sha256().unwrap();
        spec
    }

    fn evaluate_renderer_boot_contract(label: &str, spec: &SystemReleaseBuildSpecV3) -> Value {
        let root = test_temp_dir(label);
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("configuration.nix"),
            SYSTEM_RELEASE_CONFIGURATION_NIX,
        )
        .unwrap();
        fs::write(
            root.join("managed-baseline.json"),
            serde_json::to_vec(&spec.managed_baseline).unwrap(),
        )
        .unwrap();
        fs::write(
            root.join("blueprint-config.json"),
            serde_json::to_vec(&spec.blueprint.config).unwrap(),
        )
        .unwrap();
        fs::write(
            root.join("release-marker.json"),
            SystemReleaseMarkerV3::from_spec(spec)
                .unwrap()
                .canonical_bytes()
                .unwrap(),
        )
        .unwrap();
        for name in [
            "managed-agent.nix",
            "expected-state.json",
            "health-policy.json",
            "managed-agent.json",
        ] {
            fs::write(
                root.join(name),
                if name.ends_with(".nix") { "{}" } else { "{}\n" },
            )
            .unwrap();
        }
        let configuration = root.join("configuration.nix");
        let expression = format!(
            r#"
let
  module = import {configuration};
  lib = rec {{
    attrByPath = path: fallback: value:
      if path == [] then value else
      let name = builtins.head path; in
      if builtins.isAttrs value && builtins.hasAttr name value
      then attrByPath (builtins.tail path) fallback (builtins.getAttr name value)
      else fallback;
    toLower = value: builtins.replaceStrings
      [ "A" "B" "C" "D" "E" "F" "G" "H" "I" "J" "K" "L" "M"
        "N" "O" "P" "Q" "R" "S" "T" "U" "V" "W" "X" "Y" "Z" ]
      [ "a" "b" "c" "d" "e" "f" "g" "h" "i" "j" "k" "l" "m"
        "n" "o" "p" "q" "r" "s" "t" "u" "v" "w" "x" "y" "z" ] value;
    elem = builtins.elem;
    splitString = separator: value: [ value ];
    unique = values: values;
    optionalAttrs = condition: attrs: if condition then attrs else {{}};
    optional = condition: value: if condition then [ value ] else [];
    mkDefault = value: value;
  }};
  evaluated = module {{
    inherit lib;
    pkgs = {{}};
    cybexManagedAgentPackage = "/nix/store/cccccccccccccccccccccccccccccccc-cybex-agent";
    config = {{ nixpkgs.hostPlatform.system = "{system}"; }};
  }};
  rootFs = builtins.getAttr "/" evaluated.fileSystems;
  luks = evaluated.boot.initrd.luks.devices;
in {{
  assertionsPassed = builtins.all (item: item.assertion) evaluated.assertions;
  hostNameSet = builtins.hasAttr "hostName" evaluated.networking;
  systemdBoot = evaluated.boot.loader."systemd-boot".enable;
  grubEnable = evaluated.boot.loader.grub.enable;
  grubDevice = evaluated.boot.loader.grub.device;
  grubDevices = evaluated.boot.loader.grub.devices;
  grubEfiSupport = evaluated.boot.loader.grub.efiSupport;
  grubEfiInstallAsRemovable = evaluated.boot.loader.grub.efiInstallAsRemovable;
  canTouchEfiVariables = evaluated.boot.loader.efi.canTouchEfiVariables;
  efiSysMountPoint = evaluated.boot.loader.efi.efiSysMountPoint;
  rootDevice = rootFs.device;
  luksDevice = if builtins.hasAttr "cybex-root" luks
    then luks."cybex-root".device else null;
}}
"#,
            configuration = configuration.display(),
            system = spec.system,
        );
        let output = Command::new("nix")
            .args([
                "--extra-experimental-features",
                "nix-command",
                "eval",
                "--impure",
                "--json",
                "--expr",
                &expression,
            ])
            .output()
            .expect("run Nix renderer evaluation");
        if !output.status.success() {
            panic!(
                "Nix renderer evaluation failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let value = serde_json::from_slice(&output.stdout).expect("parse Nix evaluation JSON");
        let _ = fs::remove_dir_all(root);
        value
    }

    #[test]
    fn renderer_evaluates_installer_boot_contract_matrix() {
        for boot_mode in [ManagedBootMode::Uefi, ManagedBootMode::Bios] {
            for bootloader in [ManagedBootloader::Grub, ManagedBootloader::SystemdBoot] {
                if boot_mode == ManagedBootMode::Bios
                    && bootloader == ManagedBootloader::SystemdBoot
                {
                    continue;
                }
                for encrypted in [true] {
                    let mut spec = fixture();
                    spec.managed_baseline.bootloader = bootloader;
                    let underlying = "/dev/disk/by-partlabel/CYBEX-NIXOS".to_string();
                    if encrypted {
                        spec.managed_baseline.root_encryption = ManagedRootEncryptionV1 {
                            mode: ManagedRootEncryptionMode::Luks2,
                            mapper_name: Some("cybex-root".to_string()),
                            underlying_device: Some(underlying.clone()),
                        };
                        spec.managed_baseline.root_file_system.device =
                            "/dev/mapper/cybex-root".to_string();
                    }
                    match boot_mode {
                        ManagedBootMode::Uefi => {}
                        ManagedBootMode::Bios => {
                            spec.managed_baseline.disk_layout_profile =
                                ManagedDiskLayoutProfile::SingleDiskGptBios;
                            spec.managed_baseline.boot_mode = ManagedBootMode::Bios;
                            spec.managed_baseline.bootloader_device =
                                Some("/dev/disk/by-id/wwn-0x123456789abcdef0".to_string());
                            spec.managed_baseline.efi_file_system = None;
                        }
                    }
                    spec.managed_baseline_sha256 =
                        canonical_sha256(&spec.managed_baseline, MAX_STRUCTURED_INPUT_BYTES)
                            .unwrap();
                    spec.cohort_key = spec.managed_baseline_sha256.clone();
                    spec.semantic_input_sha256 = spec.computed_semantic_input_sha256().unwrap();
                    spec.validate().unwrap();
                    let label = format!(
                        "eval-{}-{}-{}",
                        match boot_mode {
                            ManagedBootMode::Uefi => "uefi",
                            ManagedBootMode::Bios => "bios",
                        },
                        match bootloader {
                            ManagedBootloader::Grub => "grub",
                            ManagedBootloader::SystemdBoot => "systemd-boot",
                        },
                        if encrypted { "luks" } else { "plain" }
                    );
                    let evaluated = evaluate_renderer_boot_contract(&label, &spec);
                    assert_eq!(evaluated["assertionsPassed"], true);
                    assert_eq!(evaluated["hostNameSet"], false);
                    assert_eq!(
                        evaluated["systemdBoot"],
                        bootloader == ManagedBootloader::SystemdBoot
                    );
                    assert_eq!(
                        evaluated["grubEnable"],
                        bootloader == ManagedBootloader::Grub
                    );
                    assert_eq!(evaluated["grubEfiInstallAsRemovable"], false);
                    assert_eq!(evaluated["efiSysMountPoint"], "/boot");
                    match boot_mode {
                        ManagedBootMode::Uefi => {
                            assert_eq!(evaluated["grubDevice"], "nodev");
                            assert_eq!(
                                evaluated["grubDevices"],
                                if bootloader == ManagedBootloader::Grub {
                                    json!(["nodev"])
                                } else {
                                    json!([])
                                }
                            );
                            assert_eq!(
                                evaluated["grubEfiSupport"],
                                bootloader == ManagedBootloader::Grub
                            );
                            assert_eq!(evaluated["canTouchEfiVariables"], true);
                        }
                        ManagedBootMode::Bios => {
                            assert_eq!(
                                evaluated["grubDevice"],
                                "/dev/disk/by-id/wwn-0x123456789abcdef0"
                            );
                            assert_eq!(
                                evaluated["grubDevices"],
                                json!(["/dev/disk/by-id/wwn-0x123456789abcdef0"])
                            );
                            assert_eq!(evaluated["grubEfiSupport"], false);
                            assert_eq!(evaluated["canTouchEfiVariables"], false);
                        }
                    }
                    assert_eq!(
                        evaluated["luksDevice"],
                        if encrypted {
                            Value::String(underlying)
                        } else {
                            Value::Null
                        }
                    );
                }
            }
        }
    }

    #[test]
    fn build_spec_v3_accepts_only_exact_typed_material() {
        let fixture = fixture();
        fixture.validate().unwrap();
        let value = serde_json::to_value(&fixture).unwrap();
        assert!(value["blueprint"].get("compiled_module_b64").is_none());
        assert!(
            value["blueprint"]
                .get("compiler_runtime_module_b64")
                .is_none()
        );
        assert_eq!(
            SystemReleaseBuildSpecV3::parse(value)
                .unwrap()
                .canonical_sha256()
                .unwrap(),
            fixture.canonical_sha256().unwrap()
        );
    }

    #[test]
    fn build_spec_v3_rejects_device_unique_luks_identity() {
        let mut spec = fixture();
        spec.managed_baseline.root_encryption.underlying_device =
            Some("/dev/disk/by-uuid/22222222-2222-2222-2222-222222222222".to_string());
        spec.managed_baseline_sha256 =
            canonical_sha256(&spec.managed_baseline, MAX_STRUCTURED_INPUT_BYTES).unwrap();
        spec.cohort_key = spec.managed_baseline_sha256.clone();
        spec.semantic_input_sha256 = spec.computed_semantic_input_sha256().unwrap();

        assert!(spec.validate().is_err());
    }

    #[test]
    fn build_spec_v3_rejects_arbitrary_nix_and_unknown_fields() {
        let fixture = fixture();
        let mut value = serde_json::to_value(&fixture).unwrap();
        value["blueprint"]["config"]["generated_nix"] = json!("{ ... }: {}");
        value["blueprint"]["config_sha256"] = json!(
            canonical_value_sha256(&value["blueprint"]["config"], MAX_STRUCTURED_INPUT_BYTES)
                .unwrap()
        );
        assert!(SystemReleaseBuildSpecV3::parse(value).is_err());

        let mut value = serde_json::to_value(&fixture).unwrap();
        value["unexpected"] = json!(true);
        assert!(SystemReleaseBuildSpecV3::parse(value).is_err());

        let mut value = serde_json::to_value(&fixture).unwrap();
        value["blueprint"]["compiled_module_b64"] = json!("e30");
        assert!(SystemReleaseBuildSpecV3::parse(value).is_err());

        let mut value = serde_json::to_value(&fixture).unwrap();
        value["blueprint"]["compiler_runtime_module_b64"] = json!("e30");
        assert!(SystemReleaseBuildSpecV3::parse(value).is_err());
    }

    #[test]
    fn build_spec_v3_rejects_digest_and_cohort_substitution() {
        let mut cohort_substitution = fixture();
        cohort_substitution.cohort_key = "c".repeat(64);
        assert!(cohort_substitution.validate().is_err());
        let mut blueprint_substitution = fixture();
        blueprint_substitution.blueprint.config_sha256 = "d".repeat(64);
        assert!(blueprint_substitution.validate().is_err());
        let mut compiled_module_substitution = fixture();
        compiled_module_substitution
            .blueprint
            .compiled_module_sha256 = "d".repeat(64);
        assert!(compiled_module_substitution.validate().is_err());
        let mut runtime_substitution = fixture();
        runtime_substitution
            .blueprint
            .compiler_runtime_module_sha256 = "d".repeat(64);
        assert!(runtime_substitution.validate().is_err());
    }

    #[test]
    fn compiler_v3_accepts_only_digest_bound_publication_material() {
        let fixture = fixture();
        assert_eq!(
            fixture.blueprint.compiled_module_sha256,
            sha256_hex(TEST_COMPILED_BLUEPRINT_MODULE_NIX.as_bytes())
        );
        assert!(fixture.validate().is_ok());
        let mut substituted = fixture;
        substituted.blueprint.compiled_module_sha256 = sha256_hex(b"different module");
        substituted.semantic_input_sha256 = substituted.computed_semantic_input_sha256().unwrap();
        assert!(substituted.validate().is_ok());
        assert_ne!(
            sha256_hex(TEST_COMPILED_BLUEPRINT_MODULE_NIX.as_bytes()),
            substituted.blueprint.compiled_module_sha256
        );
        assert!(!SYSTEM_RELEASE_COMPILER_RUNTIME_MODULE_NIX.contains("cybex-release-test-hook"));
    }

    #[test]
    fn compiler_v3_standard_golden_is_exact_and_complete() {
        let source = standard_source_config();
        let projection = system_release_compiler_v3::derive_projection(&source)
            .expect("shared Standard golden must compile");
        let mut hinted = source;
        hinted["settings"]["desktop"]["browser"]["hint"] =
            json!("Sets the browser opened by default for links and managed workflows.");
        let hinted_projection = system_release_compiler_v3::derive_projection(&hinted)
            .expect("resolved editor hint metadata must remain compiler-v3 compatible");
        assert_eq!(hinted_projection.typed_config, projection.typed_config);
        let mut application_channel = standard_source_config();
        application_channel["settings"]["apps"] = json!({
            "channel": {
                "label": "Version / channel policy",
                "value": "Channel: stable · productivity ring"
            }
        });
        let application_channel_projection =
            system_release_compiler_v3::derive_projection(&application_channel)
                .expect("application channel policy must be bound by compiler-v3");
        assert_eq!(
            application_channel_projection.typed_config["intent"]["settings"]["apps"]["channel"]["value"],
            "Channel: stable · productivity ring"
        );
        assert!(
            application_channel_projection
                .coverage
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry["path"] == "settings.apps.channel"
                    && entry["disposition"] == "release_control")
        );
        let mut managed_defaults = standard_source_config();
        managed_defaults["settings"]["security"]
            .as_object_mut()
            .unwrap()
            .remove("encryption");
        managed_defaults["settings"]["updates"]
            .as_object_mut()
            .unwrap()
            .remove("oschannel");
        let managed_defaults_projection =
            system_release_compiler_v3::derive_projection(&managed_defaults)
                .expect("omitted baseline-owned settings must use secure managed defaults");
        assert_eq!(
            managed_defaults_projection.typed_config["security"]["root_encryption"],
            "luks2_required"
        );
        assert_eq!(
            managed_defaults_projection.typed_config["release_control"]["source_os_line"],
            "26.05"
        );
        let mut incompatible_encryption = managed_defaults.clone();
        incompatible_encryption["settings"]["security"]["encryption"] = json!({"value": "None"});
        assert!(
            system_release_compiler_v3::derive_projection(&incompatible_encryption)
                .unwrap_err()
                .contains("conflicts with the managed LUKS2 baseline")
        );
        let mut incompatible_os_line = managed_defaults;
        incompatible_os_line["settings"]["updates"]["oschannel"] =
            json!({"value": "nixpkgs unstable"});
        assert!(
            system_release_compiler_v3::derive_projection(&incompatible_os_line)
                .unwrap_err()
                .contains("conflicts with the managed 26.05 stable OS line")
        );
        let mut legacy_stable = standard_source_config();
        legacy_stable["settings"]["updates"]["oschannel"]["value"] = json!("nixpkgs stable");
        let legacy_stable_projection =
            system_release_compiler_v3::derive_projection(&legacy_stable)
                .expect("legacy stable alias must resolve to the managed 26.05 baseline");
        assert_eq!(
            legacy_stable_projection.typed_config["release_control"]["source_os_line"],
            "26.05"
        );
        assert_eq!(projection.coverage.as_array().unwrap().len(), 44);
        assert_eq!(projection.typed_config["desktop"]["profile"], "Taskbar");
        assert_eq!(
            projection.typed_config["applications"]
                .as_array()
                .unwrap()
                .iter()
                .map(|application| application["package_ref"].as_str().unwrap())
                .collect::<Vec<_>>(),
            vec![
                "cybex-agent",
                "firefox-esr",
                "kdePackages.dolphin",
                "kdePackages.konsole",
                "kdePackages.spectacle",
                "kdePackages.systemsettings",
                "libreoffice",
                "thunderbird",
            ]
        );
        assert!(projection.typed_config["managed_agent_declared"] == true);
        assert!(
            projection.typed_config["applications"]
                .as_array()
                .unwrap()
                .iter()
                .any(|application| application["package_ref"] == "cybex-agent")
        );
    }

    #[test]
    fn compiler_v3_rejections_never_echo_untrusted_keys_or_values() {
        let mut source = standard_source_config();
        let untrusted_key = "attacker-private-field";
        let untrusted_value = "secret://never-echo-this";
        source[untrusted_key] = json!({"token": untrusted_value});
        let error = system_release_compiler_v3::derive_projection(&source).unwrap_err();
        assert!(!error.contains(untrusted_key));
        assert!(!error.contains(untrusted_value));

        let mut source = standard_source_config();
        source["settings"]["desktop"]["attacker-window-manager"] =
            json!({"value": "do-not-echo-this"});
        let error = system_release_compiler_v3::derive_projection(&source).unwrap_err();
        assert!(!error.contains("attacker-window-manager"));
        assert!(!error.contains("do-not-echo-this"));
        assert!(error.contains("settings.desktop"));
    }

    #[test]
    fn compiler_v3_preserves_package_choice_and_synthesizes_the_managed_agent() {
        let mut source = standard_source_config();
        source["lists"]["apps"]["installed"]["items"]
            .as_array_mut()
            .unwrap()
            .retain(|item| item["package_ref"] != "kdePackages.dolphin");
        assert!(system_release_compiler_v3::derive_projection(&source).is_ok());

        source["lists"]["apps"]["installed"]["items"]
            .as_array_mut()
            .unwrap()
            .retain(|item| item["package_ref"] != "cybex-agent");
        let projection = system_release_compiler_v3::derive_projection(&source).unwrap();
        assert!(
            projection.typed_config["applications"]
                .as_array()
                .unwrap()
                .iter()
                .any(|application| application["package_ref"] == "cybex-agent"
                    && application["package_source"] == "managed")
        );

        let mut source = standard_source_config();
        source["lists"]["apps"]["installed"]["items"][1]["package_ref"] = json!("unsafe/package");
        let error = system_release_compiler_v3::derive_projection(&source).unwrap_err();
        assert!(error.contains("package_ref"));
        assert!(!error.contains("unsafe/package"));
    }

    #[test]
    fn compiler_v3_app_metadata_cannot_change_executable_package_selection() {
        let source = standard_source_config();
        let original = system_release_compiler_v3::derive_projection(&source).unwrap();
        let mut metadata_change = source;
        let item = &mut metadata_change["lists"]["apps"]["installed"]["items"][6];
        item["id"] = json!("safe-public-id");
        item["label"] = json!("Office Suite");
        item["meta"] = json!("public catalog metadata");
        item["icon"] = json!("ph-file");
        item["source"] = json!("Blueprint catalog");
        item["version"] = json!("26.2");
        item["description"] = json!("Public description");
        item["homepage"] = json!("https://www.libreoffice.org/");
        item["license"] = json!("MPL-2.0");
        item["search_branch"] = json!("nixos-26.05");
        item["unfree"] = json!(false);
        item["icon_available"] = json!(true);
        item["platforms"] = json!(["x86_64-linux"]);
        let changed = system_release_compiler_v3::derive_projection(&metadata_change).unwrap();
        let package_refs = |projection: &system_release_compiler_v3::DerivedProjection| {
            projection.typed_config["applications"]
                .as_array()
                .unwrap()
                .iter()
                .map(|application| application["package_ref"].as_str().unwrap().to_string())
                .collect::<Vec<_>>()
        };
        assert_eq!(package_refs(&original), package_refs(&changed));
        assert_eq!(
            original.typed_config["desktop"]["favorites"],
            changed.typed_config["desktop"]["favorites"]
        );
        assert_eq!(
            original.typed_config["desktop"]["browser"],
            changed.typed_config["desktop"]["browser"]
        );

        metadata_change["lists"]["apps"]["installed"]["items"][6]["unsupported_metadata"] =
            json!("ignored execution switch");
        assert!(system_release_compiler_v3::derive_projection(&metadata_change).is_err());
    }

    #[test]
    fn compiler_v3_downloaded_nix_module_must_parse() {
        let spec = fixture();
        let root = test_temp_dir("compiler-v3-eval");
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("compiled-blueprint.nix"),
            TEST_COMPILED_BLUEPRINT_MODULE_NIX,
        )
        .unwrap();
        fs::write(
            root.join("blueprint-config.json"),
            canonical_value_bytes(&spec.blueprint.config, MAX_STRUCTURED_INPUT_BYTES).unwrap(),
        )
        .unwrap();
        fs::write(
            root.join("managed-baseline.json"),
            canonical_bytes(&spec.managed_baseline, MAX_STRUCTURED_INPUT_BYTES).unwrap(),
        )
        .unwrap();
        let module = root.join("compiled-blueprint.nix");
        let parsed = Command::new("nix-instantiate")
            .args(["--parse", module.to_str().unwrap()])
            .output()
            .expect("parse compiler-v3 Nix module");
        assert!(
            parsed.status.success(),
            "compiler-v3 module parse failed: {}",
            String::from_utf8_lossy(&parsed.stderr)
        );
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    #[ignore = "requires the production-pinned nixpkgs flake and binary cache"]
    fn compiler_v3_full_pinned_nixos_eval_covers_grub_and_systemd_boot() {
        let supported_pin = supported_system_release_nixpkgs_pin();
        let pinned_nixpkgs = supported_system_release_nixpkgs_flake();
        for bootloader in [ManagedBootloader::Grub, ManagedBootloader::SystemdBoot] {
            let mut spec = fixture();
            spec.nixpkgs_commit = supported_pin["pin"]["nixpkgs_commit"]
                .as_str()
                .unwrap()
                .to_string();
            spec.managed_baseline.bootloader = bootloader;
            spec.managed_baseline_sha256 =
                canonical_sha256(&spec.managed_baseline, MAX_STRUCTURED_INPUT_BYTES).unwrap();
            spec.cohort_key = spec.managed_baseline_sha256.clone();
            spec.semantic_input_sha256 = spec.computed_semantic_input_sha256().unwrap();
            spec.validate().unwrap();

            let label = match bootloader {
                ManagedBootloader::Grub => "pinned-nixos-grub",
                ManagedBootloader::SystemdBoot => "pinned-nixos-systemd-boot",
            };
            let root = test_temp_dir(label);
            fs::create_dir_all(&root).unwrap();
            fs::write(
                root.join("compiled-blueprint.nix"),
                TEST_COMPILED_BLUEPRINT_MODULE_NIX,
            )
            .unwrap();
            fs::write(
                root.join("blueprint-compiler-runtime.nix"),
                SYSTEM_RELEASE_COMPILER_RUNTIME_MODULE_NIX,
            )
            .unwrap();
            fs::write(
                root.join("blueprint-config.json"),
                canonical_value_bytes(&spec.blueprint.config, MAX_STRUCTURED_INPUT_BYTES).unwrap(),
            )
            .unwrap();
            fs::write(
                root.join("managed-baseline.json"),
                canonical_bytes(&spec.managed_baseline, MAX_STRUCTURED_INPUT_BYTES).unwrap(),
            )
            .unwrap();
            let expression = format!(
                r#"
let
  nixpkgs = builtins.getFlake {pin};
  evaluated = nixpkgs.lib.nixosSystem {{
    system = "x86_64-linux";
    modules = [
      {runtime}
      {compiled}
      ({{ lib, ... }}: {{
        options.services.cybex-agent.logCollectionLevel = lib.mkOption {{
          type = lib.types.str;
          default = "errors_audit";
        }};
        config = {{
          system.stateVersion = "26.05";
          fileSystems."/" = {{
            device = "/dev/mapper/cybex-root";
            fsType = "ext4";
          }};
          boot.loader.grub.enable = {grub};
          boot.loader.grub.device = "nodev";
          boot.loader.grub.efiSupport = {grub};
          boot.loader.systemd-boot.enable = {systemd_boot};
          boot.loader.efi.canTouchEfiVariables = true;
        }};
      }})
    ];
  }};
in {{
  drvPath = evaluated.config.system.build.toplevel.drvPath;
  browserCommand = evaluated.config.environment.sessionVariables.BROWSER;
  browserDesktopFile = evaluated.config.xdg.mime.defaultApplications."text/html";
  favorites = evaluated.config.cybex.desktop.taskbar.favorites;
  packagePaths = map builtins.toString evaluated.config.environment.systemPackages;
  grub = evaluated.config.boot.loader.grub.enable;
  systemdBoot = evaluated.config.boot.loader."systemd-boot".enable;
  grubGenerationLimit = evaluated.config.boot.loader.grub.configurationLimit;
  systemdBootGenerationLimit = evaluated.config.boot.loader.systemd-boot.configurationLimit;
}}
"#,
                pin = serde_json::to_string(&pinned_nixpkgs).unwrap(),
                runtime = root.join("blueprint-compiler-runtime.nix").display(),
                compiled = root.join("compiled-blueprint.nix").display(),
                grub = bootloader == ManagedBootloader::Grub,
                systemd_boot = bootloader == ManagedBootloader::SystemdBoot,
            );
            let output = Command::new("nix")
                .args([
                    "--extra-experimental-features",
                    "nix-command flakes",
                    "eval",
                    "--impure",
                    "--json",
                    "--expr",
                    &expression,
                ])
                .output()
                .expect("evaluate compiler-v3 against pinned nixpkgs");
            assert!(
                output.status.success(),
                "{label} failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let value: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert!(value["drvPath"].as_str().unwrap().ends_with(".drv"));
            assert_eq!(value["browserCommand"], "firefox-esr");
            assert_eq!(value["browserDesktopFile"], "firefox-esr.desktop");
            assert_eq!(
                value["favorites"],
                spec.blueprint.config["typed_config"]["desktop"]["favorites"]
            );
            assert_eq!(value["grub"], bootloader == ManagedBootloader::Grub);
            assert_eq!(
                value["systemdBoot"],
                bootloader == ManagedBootloader::SystemdBoot
            );
            assert_eq!(value["grubGenerationLimit"], 20);
            assert_eq!(value["systemdBootGenerationLimit"], 20);
            for package_name in [
                "firefox",
                "thunderbird",
                "dolphin",
                "systemsettings",
                "konsole",
                "spectacle",
            ] {
                assert!(
                    value["packagePaths"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|path| path.as_str().unwrap().contains(package_name)),
                    "{label} omitted {package_name}"
                );
            }
            let _ = fs::remove_dir_all(root);
        }
    }

    #[test]
    #[ignore = "requires the production-pinned nixpkgs flake and binary cache"]
    fn compiler_v3_pinned_packages_furnish_every_taskbar_desktop_file() {
        let pinned_nixpkgs = supported_system_release_nixpkgs_flake();
        for (attribute, desktop_file) in [
            ("kdePackages.dolphin", "org.kde.dolphin.desktop"),
            ("firefox-esr", "firefox-esr.desktop"),
            ("thunderbird", "thunderbird.desktop"),
            ("kdePackages.systemsettings", "systemsettings.desktop"),
            ("kdePackages.konsole", "org.kde.konsole.desktop"),
            ("kdePackages.spectacle", "org.kde.spectacle.desktop"),
        ] {
            let installable = format!("{pinned_nixpkgs}#{attribute}");
            let output = Command::new("nix")
                .args([
                    "--extra-experimental-features",
                    "nix-command flakes",
                    "build",
                    "--no-link",
                    "--print-out-paths",
                    &installable,
                ])
                .output()
                .expect("build pinned taskbar package");
            assert!(
                output.status.success(),
                "{installable} failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let store_path = String::from_utf8(output.stdout).unwrap();
            let store_path = Path::new(store_path.trim());
            assert!(
                store_path
                    .join("share/applications")
                    .join(desktop_file)
                    .is_file(),
                "{attribute} does not furnish {desktop_file}"
            );
            if attribute == "firefox-esr" {
                assert!(store_path.join("bin/firefox-esr").is_file());
            }
        }
    }

    #[test]
    fn cross_node_replicas_vary_artifact_identity_but_keep_semantic_output() {
        let origin_node = "forge-origin";
        let secondary_node = "forge-secondary";
        assert_ne!(origin_node, secondary_node);
        let origin = fixture();
        let mut replica = origin.clone();
        replica.forge_artifact_id = "018f6b61-a646-7f7c-a651-7ee13ad42f92".into();
        assert_ne!(replica.forge_artifact_id, origin.forge_artifact_id);
        assert_eq!(
            replica.computed_semantic_input_sha256().unwrap(),
            origin.semantic_input_sha256
        );
        replica.semantic_input_sha256 = replica.computed_semantic_input_sha256().unwrap();
        replica.validate().unwrap();
        assert_ne!(
            replica.canonical_sha256().unwrap(),
            origin.canonical_sha256().unwrap()
        );
        assert_eq!(
            SystemReleaseMarkerV3::from_spec(&replica)
                .unwrap()
                .canonical_bytes()
                .unwrap(),
            SystemReleaseMarkerV3::from_spec(&origin)
                .unwrap()
                .canonical_bytes()
                .unwrap()
        );
        assert_eq!(
            system_release_flake(&replica),
            system_release_flake(&origin)
        );
        assert_eq!(replica.blueprint.config, origin.blueprint.config);
        assert_eq!(
            replica.blueprint.compiled_module_sha256,
            origin.blueprint.compiled_module_sha256
        );

        let mut semantic_change = origin.clone();
        semantic_change.nixpkgs_commit = "c".repeat(40);
        semantic_change.semantic_input_sha256 =
            semantic_change.computed_semantic_input_sha256().unwrap();
        assert_ne!(
            semantic_change.semantic_input_sha256,
            origin.semantic_input_sha256
        );
        assert_ne!(
            SystemReleaseMarkerV3::from_spec(&semantic_change)
                .unwrap()
                .canonical_bytes()
                .unwrap(),
            SystemReleaseMarkerV3::from_spec(&origin)
                .unwrap()
                .canonical_bytes()
                .unwrap()
        );
    }

    #[test]
    fn production_release_inputs_reject_destructive_test_hook_material() {
        reject_production_test_hook_material(&[
            rendered_file("configuration.nix", b"{}\n".to_vec(), 0o600),
            rendered_file("flake.nix", b"{}\n".to_vec(), 0o600),
        ])
        .unwrap();
        let error = reject_production_test_hook_material(&[rendered_file(
            "cybex-release-test-hook.sh",
            b"#!/bin/sh\nexit 1\n".to_vec(),
            0o700,
        )])
        .unwrap_err();
        assert!(error.to_string().contains("destructive test hook"));
    }

    #[test]
    fn provenance_signing_matches_the_manage_envelope_contract() {
        let fixture = fixture();
        let build_spec_sha256 = fixture.canonical_sha256().unwrap();
        let provenance = ForgeSystemReleaseProvenanceV1 {
            schema: SYSTEM_RELEASE_PROVENANCE_SCHEMA.into(),
            organization_id: fixture.organization_id.clone(),
            release_id: fixture.release_id.clone(),
            variant_id: fixture.variant_id.clone(),
            forge_node_id: "forge-1".into(),
            forge_build_job_id: "018f6b61-a646-7f7c-a651-7ee13ad42f90".into(),
            forge_artifact_id: "018f6b61-a646-7f7c-a651-7ee13ad42f91".into(),
            forge_protocol: SYSTEM_RELEASE_FORGE_PROTOCOL,
            forge_version: "0.1.0".into(),
            forge_capabilities: vec!["cache_v1".into(), SYSTEM_RELEASE_BUILDER_CAPABILITY.into()],
            nixpkgs_commit: fixture.nixpkgs_commit.clone(),
            nix_version: "2.28.4".into(),
            system: fixture.system.clone(),
            baseline_version: fixture.baseline_version.clone(),
            compiler_version: fixture.compiler_version.clone(),
            input_manifest_sha256: fixture.input_manifest_sha256.clone(),
            build_spec_sha256,
            target_store_path: "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-cybex-system".into(),
            target_output_sha256: "b".repeat(64),
            target_nar_hash: "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            target_nar_size_bytes: 4096,
            target_kernel_store_path: "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-linux-kernel"
                .into(),
            target_initrd_store_path: "/nix/store/cccccccccccccccccccccccccccccccc-initrd".into(),
            target_kernel_version: "6.12.42".into(),
            release_marker_sha256: "f".repeat(64),
            closure_digest_sha256: "c".repeat(64),
            closure_manifest_sha256: "d".repeat(64),
            closure_manifest_size_bytes: 4096,
            closure_member_count: 10,
            closure_total_size_bytes: 65536,
            cache_key_id: "e".repeat(64),
            cache_key_fingerprint: "e".repeat(64),
            build_started_at: "2026-07-15T12:00:00Z".into(),
            build_completed_at: "2026-07-15T12:10:00Z".into(),
            result: "succeeded".into(),
        };
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let envelope = sign_provenance(&provenance, &key).unwrap();
        assert_eq!(envelope.content_type, SYSTEM_RELEASE_PROVENANCE_SCHEMA);
        assert_eq!(envelope.organization_id, provenance.organization_id);
        assert_eq!(
            envelope.signatures[0].key_id,
            sha256_hex(&key.verifying_key().to_bytes())
        );
        assert_eq!(
            URL_SAFE_NO_PAD
                .decode(&envelope.canonical_bytes_b64)
                .unwrap(),
            provenance.canonical_bytes().unwrap()
        );

        let mut wrong_kernel = provenance.clone();
        wrong_kernel.target_kernel_store_path = "/tmp/not-a-kernel-store-path".into();
        assert!(wrong_kernel.validate().is_err());

        let mut wrong_initrd = provenance.clone();
        wrong_initrd.target_initrd_store_path = "/tmp/not-an-initrd-store-path".into();
        assert!(wrong_initrd.validate().is_err());

        let mut wrong_kernel_version = provenance.clone();
        wrong_kernel_version.target_kernel_version = " ".repeat(129);
        assert!(wrong_kernel_version.validate().is_err());

        let mut wrong_marker = provenance.clone();
        wrong_marker.release_marker_sha256 = "F".repeat(64);
        assert!(wrong_marker.validate().is_err());

        for field in [
            "target_kernel_store_path",
            "target_initrd_store_path",
            "target_kernel_version",
            "release_marker_sha256",
        ] {
            let mut missing = serde_json::to_value(&provenance).unwrap();
            missing.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<ForgeSystemReleaseProvenanceV1>(missing).is_err());
        }
        let mut unknown = serde_json::to_value(&provenance).unwrap();
        unknown["unbound_output"] = json!(true);
        assert!(serde_json::from_value::<ForgeSystemReleaseProvenanceV1>(unknown).is_err());
    }

    #[test]
    fn nix_base32_nar_hash_normalizes_to_canonical_sri() {
        assert_eq!(
            normalize_nar_hash("sha256:1b8m03r63zqhnjf7l5wnldhh7c134ap5vpj0850ymkq1iyzicy5s")
                .unwrap(),
            "sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="
        );
        assert!(
            normalize_nar_hash("sha256:1b8m03r63zqhnjf7l5wnldhh7c134ap5vpj0850ymkq1iyzicy5e")
                .is_err()
        );
        assert!(normalize_nar_hash("sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").is_err());
    }

    fn closure_path(fill: char, name: &str) -> String {
        format!("/nix/store/{}-{name}", fill.to_string().repeat(32))
    }

    fn closure_path_info() -> (String, String, String, Value) {
        let target = closure_path('a', "system");
        let dependency = closure_path('b', "dependency");
        let leaf = closure_path('c', "leaf");
        let value = json!({
            target.clone(): {
                "narHash": "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "narSize": 300,
                "references": [leaf.clone(), dependency.clone()]
            },
            dependency.clone(): {
                "narHash": "sha256-AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
                "narSize": 200,
                "references": [leaf.clone()]
            },
            leaf.clone(): {
                "narHash": "sha256-AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
                "narSize": 100,
                "references": []
            }
        });
        (target, dependency, leaf, value)
    }

    #[test]
    fn closure_manifest_is_complete_sorted_and_deterministic() {
        let spec = fixture();
        let (target, dependency, leaf, object) = closure_path_info();
        let manifest =
            SystemReleaseClosureManifestV1::from_nix_path_info(&spec, &target, &object).unwrap();
        assert_eq!(manifest.target().unwrap().store_path, target);
        assert_eq!(manifest.total_nar_size_bytes(), 600);
        assert_eq!(
            manifest
                .members
                .iter()
                .map(|member| member.store_path.as_str())
                .collect::<Vec<_>>(),
            vec![target.as_str(), dependency.as_str(), leaf.as_str()]
        );
        assert_eq!(
            manifest.target().unwrap().references,
            vec![dependency.clone(), leaf.clone()]
        );

        let array = json!([
            {
                "path": leaf,
                "narHash": "sha256-AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
                "narSize": 100,
                "references": []
            },
            {
                "path": dependency.clone(),
                "narHash": "sha256-AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
                "narSize": 200,
                "references": [closure_path('c', "leaf")]
            },
            {
                "path": target.clone(),
                "narHash": "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "narSize": 300,
                "references": [closure_path('b', "dependency"), closure_path('c', "leaf")]
            }
        ]);
        let from_array =
            SystemReleaseClosureManifestV1::from_nix_path_info(&spec, &target, &array).unwrap();
        assert_eq!(
            manifest.canonical_bytes().unwrap(),
            from_array.canonical_bytes().unwrap()
        );
    }

    #[test]
    fn published_closure_loader_accepts_large_canonical_manifest_outside_report_body() {
        let root = test_temp_dir("large-closure-upload");
        fs::create_dir_all(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        let mut config = AppConfig::default();
        config.cache.root_dir = root.clone();
        config.server.public_base_url = "https://forge.example".into();
        let spec = fixture();
        let target_store_path = format!("/nix/store/{:032}-system", 0);
        let references = (1..=6_000)
            .map(|index| format!("/nix/store/{index:032}-dependency-{index}"))
            .collect::<Vec<_>>();
        let mut members = Vec::with_capacity(references.len() + 1);
        members.push(SystemReleaseClosureMemberV1 {
            store_path: target_store_path.clone(),
            nar_hash: "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            nar_size_bytes: 4096,
            references: references.clone(),
        });
        members.extend(
            references
                .into_iter()
                .map(|store_path| SystemReleaseClosureMemberV1 {
                    store_path,
                    nar_hash: "sha256-AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=".into(),
                    nar_size_bytes: 1024,
                    references: Vec::new(),
                }),
        );
        let manifest = SystemReleaseClosureManifestV1 {
            schema: SYSTEM_RELEASE_CLOSURE_SCHEMA.into(),
            organization_id: spec.organization_id.clone(),
            release_id: spec.release_id.clone(),
            variant_id: spec.variant_id.clone(),
            target_store_path,
            members,
        };
        let canonical = manifest.canonical_bytes().unwrap();
        assert!(canonical.len() > 1024 * 1024);
        assert!(canonical.len() <= MAX_CLOSURE_BYTES);
        let digest = sha256_hex(&canonical);
        let published =
            publish_system_release_evidence(&config, &spec, &canonical, b"provenance").unwrap();

        let loaded = load_published_system_release_closure(
            &config,
            &spec.organization_id,
            &spec.release_id,
            &spec.variant_id,
            &spec.forge_artifact_id,
            &published.closure_relative_path,
            published.closure_path.to_str().unwrap(),
            canonical.len(),
            &digest,
        )
        .unwrap();

        assert_eq!(loaded, canonical);
        assert!(
            load_published_system_release_closure(
                &config,
                &spec.organization_id,
                &spec.release_id,
                &spec.variant_id,
                &spec.forge_artifact_id,
                &published.closure_relative_path,
                published.closure_path.to_str().unwrap(),
                loaded.len(),
                &"f".repeat(64),
            )
            .is_err()
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn closure_manifest_rejects_dangling_duplicate_and_unreachable_members() {
        let spec = fixture();
        let (target, _, _, mut dangling) = closure_path_info();
        dangling[&target]["references"] = json!([closure_path('d', "missing")]);
        assert!(
            SystemReleaseClosureManifestV1::from_nix_path_info(&spec, &target, &dangling).is_err()
        );

        let (_, dependency, _, mut duplicate) = closure_path_info();
        duplicate[&dependency]["references"] =
            json!([closure_path('c', "leaf"), closure_path('c', "leaf")]);
        assert!(
            SystemReleaseClosureManifestV1::from_nix_path_info(&spec, &target, &duplicate).is_err()
        );

        let (_, _, _, mut unreachable) = closure_path_info();
        unreachable[&target]["references"] = json!([]);
        assert!(
            SystemReleaseClosureManifestV1::from_nix_path_info(&spec, &target, &unreachable)
                .is_err()
        );
    }

    #[test]
    fn release_marker_and_renderer_bind_the_persistent_agent_contract() {
        let spec = fixture();
        let marker = SystemReleaseMarkerV3::from_spec(&spec).unwrap();
        marker.validate().unwrap();
        let value: Value = serde_json::from_slice(&marker.canonical_bytes().unwrap()).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 23);
        assert_eq!(value["health_policy_sha256"], spec.health_policy_sha256);
        assert_eq!(
            value["expected_state_sha256"],
            spec.blueprint.expected_state_sha256
        );
        assert_eq!(value["semantic_input_sha256"], spec.semantic_input_sha256);
        assert_eq!(
            value["blueprint_compiled_module_sha256"],
            spec.blueprint.compiled_module_sha256
        );
        assert_eq!(
            value["compiler_runtime_module_sha256"],
            spec.blueprint.compiler_runtime_module_sha256
        );
        assert_eq!(
            value["blueprint_asset_manifest_sha256"],
            spec.blueprint.asset_manifest_sha256
        );
        assert_eq!(
            value["blueprint_extension_manifest_sha256"],
            spec.blueprint.extension_manifest_sha256
        );

        let flake = system_release_flake(&spec);
        assert!(flake.contains(&format!("github:NixOS/nixpkgs/{}", spec.nixpkgs_commit)));
        assert!(flake.contains("system = \"x86_64-linux\""));
        assert!(flake.contains("builtins.storePath packagePath"));
        assert!(
            SYSTEM_RELEASE_CONFIGURATION_NIX
                .contains("configPath = \"/var/lib/cybex-agent/config.toml\"")
        );
        assert!(
            SYSTEM_RELEASE_CONFIGURATION_NIX
                .contains("environment.etc.\"cybex/system-release/release-marker.json\"")
        );
        assert!(!SYSTEM_RELEASE_CONFIGURATION_NIX.contains("bootstrap_root_public_key"));
        assert!(!SYSTEM_RELEASE_CONFIGURATION_NIX.contains("api_url"));
    }

    #[test]
    fn blueprint_renderer_allowlist_rejects_untyped_or_executable_choices() {
        let mut invalid_profile = fixture();
        invalid_profile.blueprint.config["settings"]["desktop"]["profile"]["value"] =
            json!("arbitrary-window-manager");
        invalid_profile.blueprint.config_sha256 = canonical_value_sha256(
            &invalid_profile.blueprint.config,
            MAX_STRUCTURED_INPUT_BYTES,
        )
        .unwrap();
        assert!(invalid_profile.validate().is_err());

        let mut invalid_package = fixture();
        invalid_package.blueprint.config["lists"] = json!({
            "apps": {"required": {"items": [{"package_ref": "pkgs.hello; import ./x"}]}}
        });
        invalid_package.blueprint.config_sha256 = canonical_value_sha256(
            &invalid_package.blueprint.config,
            MAX_STRUCTURED_INPUT_BYTES,
        )
        .unwrap();
        assert!(invalid_package.validate().is_err());

        let mut executable = fixture();
        executable.blueprint.config["raw_nix"] = json!("builtins.currentSystem");
        executable.blueprint.config_sha256 =
            canonical_value_sha256(&executable.blueprint.config, MAX_STRUCTURED_INPUT_BYTES)
                .unwrap();
        assert!(executable.validate().is_err());
    }

    fn assert_blueprint_config_rejected(config: Value) {
        let mut spec = fixture();
        spec.blueprint.config = config;
        spec.blueprint.config_sha256 =
            canonical_value_sha256(&spec.blueprint.config, MAX_STRUCTURED_INPUT_BYTES).unwrap();
        assert!(spec.validate().is_err());
    }

    #[test]
    fn blueprint_renderer_rejects_every_uncompiled_domain_and_key() {
        let base = fixture().blueprint.config;

        let mut config = base.clone();
        config["settings"]["network"] = json!({"manager": {"value": "NetworkManager"}});
        assert_blueprint_config_rejected(config);

        let mut config = base.clone();
        config["settings"]["accounts"] = json!({"local_admin": {"value": "disabled"}});
        assert_blueprint_config_rejected(config);

        let mut config = base.clone();
        config["policy"] = json!({"firewall": "required"});
        assert_blueprint_config_rejected(config);

        let mut config = base.clone();
        config["settings"]["desktop"]["greeter"] = json!({"value": "GDM"});
        assert_blueprint_config_rejected(config);

        let mut config = base.clone();
        config["lists"]["users"] = json!({"required": {"items": []}});
        assert_blueprint_config_rejected(config);

        let mut config = base;
        config["lists"] = json!({
            "apps": {"required": {"items": [{
                "package_ref": "hello",
                "post_install": "ignored"
            }]}}
        });
        assert_blueprint_config_rejected(config);
    }

    #[test]
    fn blueprint_renderer_rejects_inconsistent_desktop_and_duplicate_apps() {
        let mut config = fixture().blueprint.config;
        config["settings"]["desktop"]["profile"]["value"] = json!("taskbar");
        assert_blueprint_config_rejected(config);

        let mut config = fixture().blueprint.config;
        config["lists"] = json!({
            "apps": {
                "installed": {"items": [{"package_ref": "hello"}]},
                "required": {"items": [{"package_ref": "hello"}]}
            }
        });
        assert_blueprint_config_rejected(config);

        assert!(SYSTEM_RELEASE_CONFIGURATION_NIX.contains("./compiled-blueprint.nix"));
        assert!(SYSTEM_RELEASE_CONFIGURATION_NIX.contains("./blueprint-compiler-runtime.nix"));
    }

    #[test]
    fn attestation_key_generation_is_atomic_strict_and_reloadable() {
        let root = test_temp_dir("attestation");
        let mut config = AppConfig::default();
        config.system_release.enabled = true;
        config.system_release.attestation_private_key_path = root.join("keys/private.key");
        config.system_release.attestation_public_key_path = root.join("keys/public.key");

        initialize_attestation_key(&config).unwrap();
        let identity = load_attestation_identity(&config).unwrap();
        assert_eq!(identity.key_id.len(), 64);
        assert_eq!(
            fs::metadata(&config.system_release.attestation_private_key_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&config.system_release.attestation_public_key_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
        assert_eq!(
            fs::metadata(root.join("keys"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );

        fs::set_permissions(
            &config.system_release.attestation_private_key_path,
            fs::Permissions::from_mode(0o640),
        )
        .unwrap();
        assert!(load_attestation_identity(&config).is_err());
        fs::set_permissions(
            &config.system_release.attestation_private_key_path,
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        fs::remove_file(&config.system_release.attestation_public_key_path).unwrap();
        assert!(initialize_attestation_key(&config).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn system_release_evidence_is_immutable_and_rejects_symlinks() {
        let root = test_temp_dir("evidence");
        fs::create_dir_all(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        let mut config = AppConfig::default();
        config.cache.root_dir = root.clone();
        config.server.public_base_url = "https://forge.example".into();
        let spec = fixture();

        let published =
            publish_system_release_evidence(&config, &spec, b"closure", b"provenance").unwrap();
        assert_eq!(fs::read(&published.closure_path).unwrap(), b"closure");
        assert_eq!(
            fs::metadata(&published.closure_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
        let mut published_names = fs::read_dir(published.closure_path.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        published_names.sort();
        assert_eq!(
            published_names,
            vec![
                std::ffi::OsString::from("closure.json"),
                std::ffi::OsString::from("provenance-envelope.json")
            ]
        );
        assert!(
            fs::read_dir(published.closure_path.parent().unwrap().parent().unwrap())
                .unwrap()
                .all(|entry| !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with('.'))
        );
        publish_system_release_evidence(&config, &spec, b"closure", b"provenance").unwrap();
        assert!(
            publish_system_release_evidence(&config, &spec, b"different", b"provenance").is_err()
        );
        fs::remove_file(&published.provenance_path).unwrap();
        assert!(
            publish_system_release_evidence(&config, &spec, b"closure", b"provenance").is_err(),
            "a partial final evidence directory must not be repaired in place"
        );

        let symlink = root.join("unsafe-evidence");
        std::os::unix::fs::symlink(&published.closure_path, &symlink).unwrap();
        assert!(publish_immutable_file(&symlink, b"closure").is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn renderer_materializes_content_addressed_snapshot_assets_and_extensions() {
        let mut spec = fixture();
        let wallpaper = b"wallpaper-bytes".to_vec();
        let wallpaper_sha256 = sha256_hex(&wallpaper);
        spec.blueprint.asset_manifest = json!({
            "schema": "cybex.blueprint-asset-manifest.v1",
            "assets": [{
                "logical_path": "desktop/wallpaper.png",
                "sha256": wallpaper_sha256,
                "size_bytes": wallpaper.len(),
                "media_type": "image/png",
                "target_scope": "system",
                "target_path": "/etc/cybex/blueprint-assets/desktop/wallpaper.png",
                "application_mode": "enforced"
            }]
        });
        let extension = b"{ lib, ... }: { services.openssh.enable = lib.mkForce true; }".to_vec();
        let extension_sha256 = sha256_hex(&extension);
        spec.blueprint.extension_manifest = json!({
            "schema": "cybex.blueprint-extension-manifest.v1",
            "modules": [{
                "id": "018f6b61-a646-7f7c-a651-7ee13ad42f99",
                "name": "OpenSSH",
                "version": "1",
                "sha256": extension_sha256,
                "size_bytes": extension.len(),
                "parameters": {"listen_port": 22}
            }]
        });
        let materials = SystemReleaseMaterialBundle {
            compiled_blueprint: TEST_COMPILED_BLUEPRINT_MODULE_NIX.as_bytes().to_vec(),
            assets: BTreeMap::from([(wallpaper_sha256.clone(), wallpaper)]),
            extensions: BTreeMap::from([(extension_sha256.clone(), extension)]),
        };

        let (asset_module, asset_files) =
            render_blueprint_materials(&spec.blueprint, &materials).unwrap();
        let asset_module = String::from_utf8(asset_module).unwrap();
        assert!(asset_module.contains("cybex/blueprint-assets/desktop/wallpaper.png"));
        assert_eq!(asset_files[0].name, format!("asset-{wallpaper_sha256}"));

        let (extension_module, extension_files) =
            render_blueprint_extensions(&spec.blueprint, &materials).unwrap();
        let extension_module = String::from_utf8(extension_module).unwrap();
        assert!(extension_module.contains(&format!("./extension-{extension_sha256}.nix")));
        assert!(extension_module.contains("cybexBlueprintExtensionParameters"));
        assert!(extension_module.contains("byId"));
        assert!(extension_module.contains("byName"));
        assert!(extension_module.contains("byNameVersion"));
        assert!(extension_module.contains("OpenSSH@1"));
        assert_eq!(
            extension_files[0].name,
            format!("extension-{extension_sha256}.nix")
        );

        let mut mismatched = materials;
        mismatched
            .assets
            .insert(wallpaper_sha256, b"tampered".to_vec());
        assert!(render_blueprint_materials(&spec.blueprint, &mismatched).is_err());
    }
}
