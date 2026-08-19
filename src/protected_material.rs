use std::{error::Error, fmt};

use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

const MODULAR_PASSWORD_HASH_PREFIXES: &[&str] = &[
    "$1$",
    "$2a$",
    "$2b$",
    "$2x$",
    "$2y$",
    "$5$",
    "$6$",
    "$7$",
    "$y$",
    "$gy$",
    "$argon2d$",
    "$argon2i$",
    "$argon2id$",
];
const CYBEX_LOCAL_ACCOUNT_SECRET_PREFIX: &str = "/var/lib/cybex-agent/secrets/local-accounts/";
const INSTALLER_TARGET_BUILD_INPUT_KIND: &str = "installer_target_nixos_module";
const EXPECTED_STATE_V2_SCHEMA: &str = "cybex.blueprint.expected-state.v2";
const LOCAL_ACCOUNT_PASSWORD_HASH_CHECK_KIND: &str = "local-account-password-hash";
const LOCAL_ACCOUNT_REFERENCE_DOMAIN: &[u8] = b"cybex-local-account-v2\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProtectedMaterialKind {
    ActivationSecrets,
    CredentialAssignment,
    CredentialUrl,
    ModularPasswordHash,
}

impl fmt::Display for ProtectedMaterialKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ActivationSecrets => "activation secrets",
            Self::CredentialAssignment => "a literal credential assignment",
            Self::CredentialUrl => "a credential-bearing URL",
            Self::ModularPasswordHash => "a modular password hash",
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProtectedMaterialError {
    field: &'static str,
    kind: ProtectedMaterialKind,
}

impl ProtectedMaterialError {
    fn new(field: &'static str, kind: ProtectedMaterialKind) -> Self {
        Self { field, kind }
    }
}

impl fmt::Display for ProtectedMaterialError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} contains protected material ({})",
            self.field, self.kind
        )
    }
}

impl Error for ProtectedMaterialError {}

/// Validate the entire BuildSpec before persistence. Malformed BuildSpecs are
/// rejected by the normal schema validator later, but unknown/future fields
/// must not provide a temporary credential-storage bypass before that point.
pub(crate) fn validate_build_spec(build_spec: &Value) -> Result<(), ProtectedMaterialError> {
    let installer_target_kind = build_spec
        .pointer("/build_input/kind")
        .and_then(Value::as_str)
        == Some(INSTALLER_TARGET_BUILD_INPUT_KIND);
    let installer_target =
        build_spec.get("target").and_then(Value::as_str) == Some("installer_target");
    if installer_target_kind != installer_target {
        return Err(ProtectedMaterialError::new(
            "build_spec",
            ProtectedMaterialKind::CredentialAssignment,
        ));
    }
    let mut public_projection = build_spec.clone();
    if installer_target_kind {
        let expected_state = build_spec
            .pointer("/build_input/expected_state")
            .ok_or_else(|| {
                ProtectedMaterialError::new(
                    "build_spec.build_input.expected_state",
                    ProtectedMaterialKind::CredentialAssignment,
                )
            })?;
        let contract = installer_target_expected_state_public_projection(expected_state)?;
        if build_spec
            .get("blueprint_revision_id")
            .and_then(Value::as_str)
            != Some(contract.blueprint_revision_id.as_str())
        {
            return Err(ProtectedMaterialError::new(
                "build_spec",
                ProtectedMaterialKind::CredentialAssignment,
            ));
        }
        let generated_nix = build_spec
            .pointer("/build_input/generated_nix")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let generated_nix_projection =
            installer_target_generated_nix_public_projection(generated_nix, &contract.accounts)?;
        if let Some(value) = public_projection.pointer_mut("/build_input/expected_state") {
            *value = contract.projection;
        }
        if let Some(value) = public_projection.pointer_mut("/build_input/generated_nix") {
            *value = Value::String(generated_nix_projection);
        }
    }
    validate_reusable_build_spec(&public_projection)
}

fn validate_reusable_build_spec(build_spec: &Value) -> Result<(), ProtectedMaterialError> {
    if let Some(build_input) = build_spec.get("build_input") {
        if let Some(generated_nix) = build_input.get("generated_nix").and_then(Value::as_str) {
            validate_text("build_spec.build_input.generated_nix", generated_nix)?;
        }
        if let Some(desktop_module_nix) = build_input
            .get("desktop_module_nix")
            .and_then(Value::as_str)
        {
            validate_text(
                "build_spec.build_input.desktop_module_nix",
                desktop_module_nix,
            )?;
        }
        if let Some(expected_state) = build_input.get("expected_state") {
            validate_json("build_spec.build_input.expected_state", expected_state)?;
        }
    }

    validate_json("build_spec", build_spec)
}

pub(crate) fn validate_cache_metadata(value: &Value) -> Result<(), ProtectedMaterialError> {
    validate_json("cache_metadata", value)
}

pub(crate) fn validate_generated_nix(value: &str) -> Result<(), ProtectedMaterialError> {
    validate_text("build_spec.build_input.generated_nix", value)
}

pub(crate) fn validate_desktop_module_nix(value: &str) -> Result<(), ProtectedMaterialError> {
    validate_text("build_spec.build_input.desktop_module_nix", value)
}

pub(crate) fn validate_expected_state(value: &Value) -> Result<(), ProtectedMaterialError> {
    validate_json("build_spec.build_input.expected_state", value)
}

/// Installer targets are device-specific immutable closures. Their v2
/// expected-state contract may carry a SHA-256 reference to a password hash
/// that the agent materializes separately at activation time. The digest is
/// public identity, not the hash itself, but the reusable-build scanner must
/// continue rejecting the same field for every other build kind.
pub(crate) fn validate_installer_target_expected_state(
    value: &Value,
) -> Result<(), ProtectedMaterialError> {
    let contract = installer_target_expected_state_public_projection(value)?;
    validate_json(
        "build_spec.build_input.expected_state",
        &contract.projection,
    )
}

pub(crate) fn validate_installer_target_generated_nix(
    generated_nix: &str,
    expected_state: &Value,
) -> Result<(), ProtectedMaterialError> {
    let contract = installer_target_expected_state_public_projection(expected_state)?;
    let projection =
        installer_target_generated_nix_public_projection(generated_nix, &contract.accounts)?;
    validate_text("build_spec.build_input.generated_nix", &projection)
}

/// Installer closures import four independent Nix modules. Account integrity
/// must therefore be checked on every surface, not just the generated
/// Blueprint. Non-Blueprint modules are server-derived and may not own any
/// `users` option; the Blueprint surface is validated separately against its
/// exact expected-state overlay.
pub(crate) fn validate_installer_target_non_blueprint_module(
    field: &'static str,
    module: &str,
) -> Result<(), ProtectedMaterialError> {
    if nix_module_may_define_users(module) {
        return Err(ProtectedMaterialError::new(
            field,
            ProtectedMaterialKind::CredentialAssignment,
        ));
    }
    validate_text(field, module)
}

fn installer_target_generated_nix_public_projection(
    generated_nix: &str,
    accounts: &[InstallerTargetLocalAccount],
) -> Result<String, ProtectedMaterialError> {
    if !installer_target_generated_nix_has_exact_account_overlay(generated_nix, accounts) {
        return Err(ProtectedMaterialError::new(
            "build_spec.build_input.generated_nix",
            ProtectedMaterialKind::CredentialAssignment,
        ));
    }
    let mut projection = generated_nix.to_string();
    for account in accounts {
        projection = projection.replace(
            &format!(
                "\"{CYBEX_LOCAL_ACCOUNT_SECRET_PREFIX}{}\"",
                account.password_secret_ref
            ),
            "\"/run/credentials/validated-local-account-reference\"",
        );
    }
    Ok(projection)
}

#[derive(Clone, Debug)]
struct InstallerTargetLocalAccount {
    username: String,
    display_name: String,
    groups: Vec<String>,
    password_secret_ref: String,
}

#[derive(Clone, Debug)]
struct InstallerTargetExpectedStateContract {
    projection: Value,
    blueprint_revision_id: String,
    accounts: Vec<InstallerTargetLocalAccount>,
}

const CYBEX_ADMIN_ACCOUNT_PREFIX: &str = "  users.users.cybex-admin = {\n";
const CYBEX_KIOSK_ACCOUNT_PREFIX: &str = "  users.users.cybex-kiosk = {\n";

fn installer_target_expected_state_public_projection(
    value: &Value,
) -> Result<InstallerTargetExpectedStateContract, ProtectedMaterialError> {
    let invalid = || {
        ProtectedMaterialError::new(
            "build_spec.build_input.expected_state",
            ProtectedMaterialKind::CredentialAssignment,
        )
    };
    let mut projection = value.clone();
    let object = projection.as_object_mut().ok_or_else(invalid)?;
    if object.get("schema").and_then(Value::as_str) != Some(EXPECTED_STATE_V2_SCHEMA)
        || object.get("compiler_version").and_then(Value::as_u64) != Some(2)
    {
        return Err(invalid());
    }
    let deployment = object
        .get("deployment")
        .and_then(Value::as_object)
        .ok_or_else(invalid)?;
    let revision_text = deployment
        .get("blueprint_revision_id")
        .and_then(Value::as_str)
        .ok_or_else(invalid)?
        .to_string();
    let revision = Uuid::parse_str(&revision_text)
        .ok()
        .filter(|value| value.hyphenated().to_string() == revision_text)
        .ok_or_else(invalid)?;
    let profile_generation = deployment
        .get("local_account_profile_generation_sha256")
        .and_then(Value::as_str)
        .filter(|value| safe_lower_sha256(value))
        .map(str::to_string);
    let checks = object
        .get_mut("checks")
        .and_then(Value::as_array_mut)
        .filter(|checks| checks.len() <= 128)
        .ok_or_else(invalid)?;
    let mut password_secret_refs = std::collections::BTreeMap::new();
    for check in checks {
        let Some(check) = check.as_object_mut() else {
            continue;
        };
        if check.get("kind").and_then(Value::as_str) != Some(LOCAL_ACCOUNT_PASSWORD_HASH_CHECK_KIND)
        {
            continue;
        }
        if !object_has_exact_keys(check, &["id", "kind", "expected"]) {
            return Err(invalid());
        }
        let check_id = check
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(invalid)?
            .to_string();
        let expected = check
            .get_mut("expected")
            .and_then(Value::as_object_mut)
            .ok_or_else(invalid)?;
        if !object_has_exact_keys(expected, &["username", "password_secret_ref"]) {
            return Err(invalid());
        }
        let username = expected
            .get("username")
            .and_then(Value::as_str)
            .filter(|username| safe_local_account_username(username))
            .ok_or_else(invalid)?
            .to_string();
        if check_id != format!("identity.local-account.{username}.password") {
            return Err(invalid());
        }
        let password_secret_ref = expected
            .get("password_secret_ref")
            .and_then(Value::as_str)
            .filter(|value| safe_lower_sha256(value))
            .ok_or_else(invalid)?
            .to_string();
        let Some(profile_generation) = profile_generation.as_deref() else {
            return Err(invalid());
        };
        if password_secret_ref != local_account_secret_ref(revision, profile_generation, &username)
            || password_secret_refs
                .insert(username.clone(), password_secret_ref)
                .is_some()
        {
            return Err(invalid());
        }
        // Scan the real shape above, then omit only this public identifier
        // from the generic credential-key scanner. No protected value is
        // copied into, persisted from, or written through this projection.
        expected.remove("password_secret_ref");
    }
    let inventory_checks = object["checks"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|check| {
            check.get("kind").and_then(Value::as_str) == Some("local-account-inventory")
        })
        .collect::<Vec<_>>();
    if inventory_checks.len() != 1
        || inventory_checks[0].get("id").and_then(Value::as_str)
            != Some("identity.local-account.inventory")
    {
        return Err(invalid());
    }
    let inventory_accounts = inventory_checks[0]
        .pointer("/expected/accounts")
        .and_then(Value::as_array)
        .filter(|accounts| accounts.len() <= 128)
        .ok_or_else(invalid)?;
    if profile_generation.is_some() == inventory_accounts.is_empty()
        || password_secret_refs.len() != inventory_accounts.len()
    {
        return Err(invalid());
    }
    let mut accounts = Vec::with_capacity(inventory_accounts.len());
    for account in inventory_accounts {
        let account = account.as_object().ok_or_else(invalid)?;
        if !object_has_exact_keys(account, &["username", "display_name", "admin", "groups"]) {
            return Err(invalid());
        }
        let username = account
            .get("username")
            .and_then(Value::as_str)
            .filter(|value| safe_local_account_username(value))
            .ok_or_else(invalid)?;
        let display_name = account
            .get("display_name")
            .and_then(Value::as_str)
            .filter(|value| {
                !value.is_empty()
                    && value.len() <= 256
                    && !value.contains(':')
                    && !value.chars().any(char::is_control)
            })
            .ok_or_else(invalid)?;
        account
            .get("admin")
            .and_then(Value::as_bool)
            .ok_or_else(invalid)?;
        let groups = account
            .get("groups")
            .and_then(Value::as_array)
            .filter(|groups| groups.len() <= 32)
            .ok_or_else(invalid)?
            .iter()
            .map(|group| {
                group
                    .as_str()
                    .filter(|value| safe_group_name(value))
                    .map(str::to_string)
                    .ok_or_else(invalid)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let password_secret_ref = password_secret_refs.remove(username).ok_or_else(invalid)?;
        accounts.push(InstallerTargetLocalAccount {
            username: username.to_string(),
            display_name: display_name.to_string(),
            groups,
            password_secret_ref,
        });
    }
    if !password_secret_refs.is_empty() {
        return Err(invalid());
    }
    Ok(InstallerTargetExpectedStateContract {
        projection,
        blueprint_revision_id: revision_text,
        accounts,
    })
}

pub(crate) fn local_account_secret_ref(
    revision: Uuid,
    profile_generation: &str,
    username: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(LOCAL_ACCOUNT_REFERENCE_DOMAIN);
    hasher.update(revision.hyphenated().to_string().as_bytes());
    hasher.update(b":");
    hasher.update(profile_generation.as_bytes());
    hasher.update(b"\0");
    hasher.update(username.as_bytes());
    hex::encode(hasher.finalize())
}

fn installer_target_generated_nix_has_exact_account_overlay(
    generated_nix: &str,
    accounts: &[InstallerTargetLocalAccount],
) -> bool {
    if !reserved_account_blocks_are_canonical(generated_nix)
        || nix_blueprint_uses_account_metaprogramming(generated_nix)
        || !nix_module_returns_literal_attrset_with_direct_user_assignments(generated_nix)
    {
        return false;
    }
    if accounts.is_empty() {
        return !generated_nix.contains(CYBEX_LOCAL_ACCOUNT_SECRET_PREFIX)
            && nix_user_assignment_contract_is_exact(generated_nix, accounts);
    }
    let mut expected_overlay = String::from("  # Dynamic local-account profile overlay\n");
    for account in accounts {
        expected_overlay.push_str(&format!(
            "  users.users.{} = {{\n",
            json_string(&account.username)
        ));
        expected_overlay.push_str("    isNormalUser = true;\n");
        expected_overlay.push_str(&format!(
            "    description = {};\n",
            json_string(&account.display_name)
        ));
        expected_overlay.push_str("    extraGroups = [");
        for group in &account.groups {
            expected_overlay.push(' ');
            expected_overlay.push_str(&json_string(group));
        }
        expected_overlay.push_str(" ];\n");
        expected_overlay.push_str(&format!(
            "    hashedPasswordFile = \"{CYBEX_LOCAL_ACCOUNT_SECRET_PREFIX}{}\";\n",
            account.password_secret_ref
        ));
        expected_overlay.push_str("  };\n");
    }
    let Some(overlay_offset) = generated_nix.find(&expected_overlay) else {
        return false;
    };
    generated_nix.matches(&expected_overlay).count() == 1
        && nix_offset_is_code(
            generated_nix,
            overlay_offset + expected_overlay.find("users.users").unwrap_or(0),
        )
        && generated_nix
            .match_indices(CYBEX_LOCAL_ACCOUNT_SECRET_PREFIX)
            .count()
            == accounts.len()
        && nix_user_assignment_contract_is_exact(generated_nix, accounts)
}

fn nix_module_returns_literal_attrset_with_direct_user_assignments(source: &str) -> bool {
    let body_offset = if source.starts_with("{ config, pkgs, lib, ... }:\nlet\n") {
        let marker = "\nin\n{\n";
        if source.matches(marker).count() != 1 {
            return false;
        }
        source.find(marker).unwrap_or(0) + "\nin\n".len()
    } else if source.starts_with("{ ... }:\n{\n") {
        "{ ... }:\n".len()
    } else {
        return false;
    };
    let Some(tokens) = nix_tokens(source) else {
        return false;
    };
    let Some(body_index) = tokens
        .iter()
        .position(|token| token.start == body_offset && token.kind == NixTokenKind::LeftBrace)
    else {
        return false;
    };
    if tokens.iter().skip(body_index + 1).any(|token| {
        matches!(&token.kind, NixTokenKind::Identifier(value) if value == "let" || value == "in")
    }) {
        return false;
    }
    if tokens
        .iter()
        .enumerate()
        .take(body_index)
        .any(|(index, _)| is_literal_users_users_root(&tokens, index))
    {
        return false;
    }
    let mut depth = 0usize;
    let mut close_index = None;
    for (index, token) in tokens.iter().enumerate().skip(body_index) {
        if index > body_index && is_literal_users_users_root(&tokens, index) && depth != 1 {
            return false;
        }
        match token.kind {
            NixTokenKind::LeftBrace => depth += 1,
            NixTokenKind::RightBrace => {
                let Some(next_depth) = depth.checked_sub(1) else {
                    return false;
                };
                depth = next_depth;
                if depth == 0 {
                    close_index = Some(index);
                    break;
                }
            }
            _ => {}
        }
    }
    close_index == Some(tokens.len().saturating_sub(1)) && source.ends_with("}\n")
}

fn is_literal_users_users_root(tokens: &[NixToken], index: usize) -> bool {
    matches!(
        tokens.get(index).map(|token| &token.kind),
        Some(NixTokenKind::Identifier(first) | NixTokenKind::String(first)) if first == "users"
    ) && tokens
        .get(index + 1)
        .is_some_and(|token| token.kind == NixTokenKind::Dot)
        && matches!(
            tokens.get(index + 2).map(|token| &token.kind),
            Some(NixTokenKind::Identifier(second) | NixTokenKind::String(second)) if second == "users"
        )
}

fn nix_blueprint_uses_account_metaprogramming(source: &str) -> bool {
    let Some(tokens) = nix_tokens(source) else {
        return true;
    };
    let forbidden = [
        "imports",
        "import",
        "inherit",
        "listToAttrs",
        "setAttrByPath",
        "recursiveUpdate",
        "mapAttrs",
        "mapAttrs'",
        "genAttrs",
        "nameValuePair",
        "mkMerge",
        "scopedImport",
        "fromJSON",
        "fromTOML",
        "removeAttrs",
        "filterAttrs",
        // NixOS aliases this option to users.users. Treat every spelling as
        // account-owning input so an installer module cannot shadow the
        // authenticated local-account overlay through the legacy alias.
        "extraUsers",
    ];
    tokens
        .iter()
        .enumerate()
        .any(|(index, token)| match &token.kind {
            NixTokenKind::Identifier(value) => forbidden.contains(&value.as_str()),
            NixTokenKind::String(value) => {
                nix_token_is_attribute_segment(&tokens, index)
                    && (value.contains("${") || forbidden.contains(&value.as_str()))
            }
            _ => false,
        })
}

fn reserved_account_blocks_are_canonical(source: &str) -> bool {
    let admin_count = source.matches(CYBEX_ADMIN_ACCOUNT_PREFIX).count();
    let kiosk_count = source.matches(CYBEX_KIOSK_ACCOUNT_PREFIX).count();
    if admin_count > 1 || kiosk_count > 1 {
        return false;
    }
    if admin_count == 1 {
        let Some((_, rest)) = source.split_once(CYBEX_ADMIN_ACCOUNT_PREFIX) else {
            return false;
        };
        let Some((block, _)) = rest.split_once("  };\n") else {
            return false;
        };
        let lines = block.lines().collect::<Vec<_>>();
        if lines.len() < 4
            || lines[0] != "    isNormalUser = true;"
            || lines[1] != "    description = \"Cybex break-glass administrator\";"
            || !matches!(
                lines[2],
                "    extraGroups = [ \"wheel\" \"networkmanager\" \"video\" \"audio\" ];"
                    | "    extraGroups = [ \"wheel\" \"networkmanager\" \"video\" \"audio\" ] ++ [ \"docker\" ];"
                    | "    extraGroups = [ \"wheel\" \"video\" \"audio\" ];"
                    | "    extraGroups = [ \"wheel\" \"video\" \"audio\" ] ++ [ \"docker\" ];"
            )
            || lines[3] != "    hashedPassword = \"!\";"
            || (lines.len() > 4
                && (lines[4] != "    openssh.authorizedKeys.keys = ["
                    || lines.last() != Some(&"    ];")
                    || lines[5..lines.len() - 1]
                        .iter()
                        .any(|line| !canonical_public_ssh_key_line(line))))
        {
            return false;
        }
    }
    if kiosk_count == 1 {
        let Some((_, rest)) = source.split_once(CYBEX_KIOSK_ACCOUNT_PREFIX) else {
            return false;
        };
        let Some((block, _)) = rest.split_once("  };\n") else {
            return false;
        };
        let with_networkmanager = "    isNormalUser = true;\n    description = \"Cybex kiosk session\";\n    extraGroups = [ \"networkmanager\" \"video\" \"audio\" ];\n    hashedPassword = \"!\";\n";
        let without_networkmanager = "    isNormalUser = true;\n    description = \"Cybex kiosk session\";\n    extraGroups = [ \"video\" \"audio\" ];\n    hashedPassword = \"!\";\n";
        if block != with_networkmanager && block != without_networkmanager {
            return false;
        }
    }
    true
}

fn canonical_public_ssh_key_line(line: &str) -> bool {
    let Some(key) = line
        .strip_prefix("      \"")
        .and_then(|value| value.strip_suffix('"'))
    else {
        return false;
    };
    let mut parts = key.split_whitespace();
    let Some(key_type) = parts.next() else {
        return false;
    };
    let Some(material) = parts.next() else {
        return false;
    };
    parts.next().is_none()
        && (matches!(key_type, "ssh-ed25519" | "ssh-rsa")
            || key_type.starts_with("ecdsa-sha2-")
            || key_type.starts_with("sk-ssh-"))
        && material.len() <= 8192
        && !material.is_empty()
        && material.len() % 4 != 1
        && material
            .trim_end_matches('=')
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/'))
        && material
            .strip_prefix(material.trim_end_matches('='))
            .is_some_and(|padding| padding.len() <= 2 && padding.bytes().all(|byte| byte == b'='))
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum NixTokenKind {
    Identifier(String),
    String(String),
    Dot,
    Equals,
    Dollar,
    LeftBrace,
    RightBrace,
    Other,
}

#[derive(Clone, Debug)]
struct NixToken {
    kind: NixTokenKind,
    start: usize,
}

fn nix_tokens(source: &str) -> Option<Vec<NixToken>> {
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            byte if byte.is_ascii_whitespace() => index += 1,
            b'#' => {
                index += 1;
                while index < bytes.len() && bytes[index] != b'\n' {
                    index += 1;
                }
            }
            b'/' if bytes.get(index + 1) == Some(&b'*') => {
                index += 2;
                let mut depth = 1usize;
                while index < bytes.len() && depth > 0 {
                    if bytes.get(index..index + 2) == Some(b"/*") {
                        depth = depth.checked_add(1)?;
                        index += 2;
                    } else if bytes.get(index..index + 2) == Some(b"*/") {
                        depth -= 1;
                        index += 2;
                    } else {
                        index += 1;
                    }
                }
                if depth != 0 {
                    return None;
                }
            }
            b'\'' if bytes.get(index + 1) == Some(&b'\'') => {
                index += 2;
                let mut closed = false;
                while index < bytes.len() {
                    if bytes.get(index..index + 3) == Some(b"'''") {
                        index += 3;
                    } else if bytes.get(index..index + 2) == Some(b"''") {
                        index += 2;
                        closed = true;
                        break;
                    } else {
                        index += 1;
                    }
                }
                if !closed {
                    return None;
                }
            }
            b'"' => {
                let start = index;
                index += 1;
                let mut escaped = false;
                while index < bytes.len() {
                    match bytes[index] {
                        b'"' if !escaped => {
                            index += 1;
                            break;
                        }
                        b'\\' if !escaped => escaped = true,
                        _ => escaped = false,
                    }
                    index += 1;
                }
                if bytes.get(index.wrapping_sub(1)) != Some(&b'"') {
                    return None;
                }
                let value = serde_json::from_str::<String>(&source[start..index]).ok()?;
                tokens.push(NixToken {
                    kind: NixTokenKind::String(value),
                    start,
                });
            }
            b'.' => {
                tokens.push(NixToken {
                    kind: NixTokenKind::Dot,
                    start: index,
                });
                index += 1;
            }
            b'=' => {
                tokens.push(NixToken {
                    kind: NixTokenKind::Equals,
                    start: index,
                });
                index += 1;
            }
            b'$' => {
                tokens.push(NixToken {
                    kind: NixTokenKind::Dollar,
                    start: index,
                });
                index += 1;
            }
            b'{' => {
                tokens.push(NixToken {
                    kind: NixTokenKind::LeftBrace,
                    start: index,
                });
                index += 1;
            }
            b'}' => {
                tokens.push(NixToken {
                    kind: NixTokenKind::RightBrace,
                    start: index,
                });
                index += 1;
            }
            byte if byte.is_ascii_alphabetic() || byte == b'_' => {
                let start = index;
                index += 1;
                while bytes.get(index).is_some_and(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'\'')
                }) {
                    index += 1;
                }
                tokens.push(NixToken {
                    kind: NixTokenKind::Identifier(source[start..index].to_string()),
                    start,
                });
            }
            _ => {
                tokens.push(NixToken {
                    kind: NixTokenKind::Other,
                    start: index,
                });
                index += 1;
            }
        }
    }
    Some(tokens)
}

fn nix_offset_is_code(source: &str, offset: usize) -> bool {
    nix_tokens(source).is_some_and(|tokens| tokens.iter().any(|token| token.start == offset))
}

fn nix_module_may_define_users(source: &str) -> bool {
    let Some(tokens) = nix_tokens(source) else {
        return true;
    };
    let dangerous_constructors = [
        "listToAttrs",
        "setAttrByPath",
        "recursiveUpdate",
        "mapAttrs",
        "mapAttrs'",
        "genAttrs",
        "nameValuePair",
        "mkMerge",
        "scopedImport",
        "fromJSON",
        "fromTOML",
        "removeAttrs",
        "filterAttrs",
    ];
    tokens
        .iter()
        .enumerate()
        .any(|(index, token)| match &token.kind {
            NixTokenKind::Identifier(value) => {
                value == "users"
                    || value == "extraUsers"
                    || value == "imports"
                    || value == "import"
                    || value == "inherit"
                    || dangerous_constructors.contains(&value.as_str())
            }
            NixTokenKind::String(value) => {
                nix_token_is_attribute_segment(&tokens, index)
                    && (value.contains("${")
                        || value == "users"
                        || value == "extraUsers"
                        || value == "imports"
                        || value == "import"
                        || value == "inherit"
                        || dangerous_constructors.contains(&value.as_str()))
            }
            NixTokenKind::Dollar => dynamic_users_path_may_override_accounts(&tokens, index),
            _ => false,
        })
}

fn nix_token_is_attribute_segment(tokens: &[NixToken], index: usize) -> bool {
    let preceded_by_dot = index
        .checked_sub(1)
        .and_then(|previous| tokens.get(previous))
        .is_some_and(|token| token.kind == NixTokenKind::Dot);
    let followed_by_dot = tokens
        .get(index + 1)
        .is_some_and(|token| token.kind == NixTokenKind::Dot);
    let followed_by_assignment = tokens
        .get(index + 1)
        .is_some_and(|token| token.kind == NixTokenKind::Equals)
        && !tokens
            .get(index + 2)
            .is_some_and(|token| token.kind == NixTokenKind::Equals)
        && !index
            .checked_sub(1)
            .and_then(|previous| tokens.get(previous))
            .is_some_and(|token| token.kind == NixTokenKind::Equals);
    preceded_by_dot || followed_by_dot || followed_by_assignment
}

fn nix_user_assignment_contract_is_exact(
    source: &str,
    accounts: &[InstallerTargetLocalAccount],
) -> bool {
    let Some(tokens) = nix_tokens(source) else {
        return false;
    };
    let expected = accounts
        .iter()
        .map(|account| (account.username.as_str(), 0usize))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut observed = expected.clone();
    let mut reserved_observed =
        std::collections::BTreeMap::from([("cybex-admin", 0usize), ("cybex-kiosk", 0usize)]);
    let mut index = 0usize;
    while index < tokens.len() {
        let first = match &tokens[index].kind {
            NixTokenKind::Identifier(value) | NixTokenKind::String(value) => value,
            NixTokenKind::Dollar => {
                if dynamic_users_path_may_override_accounts(&tokens, index) {
                    return false;
                }
                index += 1;
                continue;
            }
            _ => {
                index += 1;
                continue;
            }
        };
        if first == "users"
            && tokens
                .get(index + 1)
                .is_some_and(|token| token.kind == NixTokenKind::Equals)
        {
            return false;
        }
        let is_users_users = first == "users"
            && tokens
                .get(index + 1)
                .is_some_and(|token| token.kind == NixTokenKind::Dot)
            && matches!(
                tokens.get(index + 2).map(|token| &token.kind),
                Some(NixTokenKind::Identifier(second) | NixTokenKind::String(second)) if second == "users"
            );
        if !is_users_users {
            index += 1;
            continue;
        }
        match tokens.get(index + 3).map(|token| &token.kind) {
            Some(NixTokenKind::Equals) => return false,
            Some(NixTokenKind::Dot) => {
                let Some(attribute) = tokens.get(index + 4).map(|token| &token.kind) else {
                    return false;
                };
                let attribute = match attribute {
                    NixTokenKind::Identifier(value) | NixTokenKind::String(value) => value,
                    NixTokenKind::Dollar => return false,
                    _ => {
                        index += 1;
                        continue;
                    }
                };
                if attribute.contains("${") {
                    return false;
                }
                if let Some(count) = observed.get_mut(attribute.as_str()) {
                    match tokens.get(index + 5).map(|token| &token.kind) {
                        Some(NixTokenKind::Equals) => {}
                        Some(NixTokenKind::Dot) => return false,
                        _ => return false,
                    }
                    *count += 1;
                } else if let Some(count) = reserved_observed.get_mut(attribute.as_str()) {
                    if tokens.get(index + 5).map(|token| &token.kind) != Some(&NixTokenKind::Equals)
                        || tokens[index].start
                            != match attribute.as_str() {
                                "cybex-admin" => {
                                    source.find(CYBEX_ADMIN_ACCOUNT_PREFIX).map(|offset| {
                                        offset
                                            + CYBEX_ADMIN_ACCOUNT_PREFIX
                                                .find("users.users")
                                                .unwrap_or(0)
                                    })
                                }
                                "cybex-kiosk" => {
                                    source.find(CYBEX_KIOSK_ACCOUNT_PREFIX).map(|offset| {
                                        offset
                                            + CYBEX_KIOSK_ACCOUNT_PREFIX
                                                .find("users.users")
                                                .unwrap_or(0)
                                    })
                                }
                                _ => None,
                            }
                            .unwrap_or(usize::MAX)
                    {
                        return false;
                    }
                    *count += 1;
                    if *count > 1 {
                        return false;
                    }
                } else {
                    // Immutable Blueprint modules may declare only Cybex's two
                    // appliance accounts here. Every ordinary local account
                    // must come from the exact authenticated overlay above.
                    return false;
                }
            }
            _ => {}
        }
        index += 1;
    }
    observed.values().all(|count| *count == 1)
}

fn dynamic_users_path_may_override_accounts(tokens: &[NixToken], index: usize) -> bool {
    if tokens.get(index).map(|token| &token.kind) != Some(&NixTokenKind::Dollar)
        || tokens.get(index + 1).map(|token| &token.kind) != Some(&NixTokenKind::LeftBrace)
    {
        return false;
    }
    let mut depth = 1usize;
    let mut cursor = index + 2;
    while cursor < tokens.len() && depth > 0 {
        match tokens[cursor].kind {
            NixTokenKind::LeftBrace => depth += 1,
            NixTokenKind::RightBrace => depth -= 1,
            _ => {}
        }
        cursor += 1;
    }
    if depth != 0 {
        return true;
    }
    if !matches!(
        tokens.get(cursor).map(|token| &token.kind),
        Some(NixTokenKind::Dot | NixTokenKind::Equals)
    ) {
        return false;
    }
    tokens[cursor..tokens.len().min(cursor + 32)]
        .iter()
        .take_while(|token| {
            !matches!(
                token.kind,
                NixTokenKind::Other | NixTokenKind::LeftBrace | NixTokenKind::RightBrace
            )
        })
        .any(|token| token.kind == NixTokenKind::Equals)
}

fn json_string(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_string())
}

#[cfg(test)]
pub(crate) fn installer_target_test_generated_nix(
    accounts: &[(&str, &str, bool, &[&str], &str)],
) -> String {
    let accounts = accounts
        .iter()
        .map(
            |(username, display_name, _admin, groups, password_secret_ref)| {
                InstallerTargetLocalAccount {
                    username: (*username).to_string(),
                    display_name: (*display_name).to_string(),
                    groups: groups.iter().map(|group| (*group).to_string()).collect(),
                    password_secret_ref: (*password_secret_ref).to_string(),
                }
            },
        )
        .collect::<Vec<_>>();
    let mut overlay = String::from("{ ... }:\n{\n");
    let marker = "  # Dynamic local-account profile overlay\n";
    overlay.push_str(marker);
    for account in &accounts {
        overlay.push_str(&format!(
            "  users.users.{} = {{\n    isNormalUser = true;\n    description = {};\n    extraGroups = [",
            json_string(&account.username),
            json_string(&account.display_name)
        ));
        for group in &account.groups {
            overlay.push(' ');
            overlay.push_str(&json_string(group));
        }
        overlay.push_str(&format!(
            " ];\n    hashedPasswordFile = \"{CYBEX_LOCAL_ACCOUNT_SECRET_PREFIX}{}\";\n  }};\n",
            account.password_secret_ref
        ));
    }
    overlay.push_str("}\n");
    overlay
}

fn safe_group_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
}

fn object_has_exact_keys(object: &serde_json::Map<String, Value>, expected: &[&str]) -> bool {
    object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key))
}

fn safe_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn safe_local_account_username(value: &str) -> bool {
    if value.is_empty() || value.len() > 32 {
        return false;
    }
    let mut chars = value.chars();
    chars
        .next()
        .is_some_and(|ch| ch.is_ascii_lowercase() || ch == '_')
        && chars.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '_' | '-'))
        && !matches!(
            value,
            "root" | "cybex-admin" | "cybex-kiosk" | "nobody" | "systemd"
        )
}

pub(crate) fn contains_modular_password_hash(text: &str) -> bool {
    next_modular_password_hash(text).is_some()
}

pub(crate) fn next_modular_password_hash(text: &str) -> Option<(usize, usize)> {
    let lower = text.to_ascii_lowercase();
    let (start, prefix_len) = MODULAR_PASSWORD_HASH_PREFIXES
        .iter()
        .filter_map(|prefix| lower.find(prefix).map(|start| (start, prefix.len())))
        .min_by_key(|(start, _)| *start)?;
    let value_start = start + prefix_len;
    let mut end = value_start;
    for (offset, ch) in text[value_start..].char_indices() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '$' | '.' | '/' | '+' | '=' | ',' | '-') {
            end = value_start + offset + ch.len_utf8();
        } else {
            break;
        }
    }
    Some((start, end))
}

fn validate_json(field: &'static str, value: &Value) -> Result<(), ProtectedMaterialError> {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                let canonical = canonical_key(key);
                if canonical == "activationsecrets" {
                    return Err(ProtectedMaterialError::new(
                        field,
                        ProtectedMaterialKind::ActivationSecrets,
                    ));
                }
                if is_credential_key(&canonical)
                    && !json_credential_value_is_safe_reference(&canonical, value)
                {
                    return Err(ProtectedMaterialError::new(
                        field,
                        ProtectedMaterialKind::CredentialAssignment,
                    ));
                }
                validate_json(field, value)?;
            }
            Ok(())
        }
        Value::Array(values) => {
            for value in values {
                validate_json(field, value)?;
            }
            Ok(())
        }
        Value::String(value) => validate_text(field, value),
        Value::Null | Value::Bool(_) | Value::Number(_) => Ok(()),
    }
}

fn validate_text(field: &'static str, text: &str) -> Result<(), ProtectedMaterialError> {
    if contains_modular_password_hash(text) {
        return Err(ProtectedMaterialError::new(
            field,
            ProtectedMaterialKind::ModularPasswordHash,
        ));
    }
    if contains_cybex_activation_secret_reference(text) {
        return Err(ProtectedMaterialError::new(
            field,
            ProtectedMaterialKind::ActivationSecrets,
        ));
    }
    if contains_credential_url(text) {
        return Err(ProtectedMaterialError::new(
            field,
            ProtectedMaterialKind::CredentialUrl,
        ));
    }
    if contains_unsafe_credential_assignment(text) {
        return Err(ProtectedMaterialError::new(
            field,
            ProtectedMaterialKind::CredentialAssignment,
        ));
    }
    Ok(())
}

fn contains_cybex_activation_secret_reference(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    let parts = lower
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    parts
        .iter()
        .any(|part| matches!(*part, "activationsecret" | "activationsecrets"))
        || parts
            .windows(2)
            .any(|parts| parts[0] == "activation" && matches!(parts[1], "secret" | "secrets"))
}

fn contains_unsafe_credential_assignment(text: &str) -> bool {
    for (equals, _) in text.match_indices('=') {
        let bytes = text.as_bytes();
        if bytes.get(equals.wrapping_sub(1)) == Some(&b'=') || bytes.get(equals + 1) == Some(&b'=')
        {
            continue;
        }
        let Some(key) = assignment_key(text, equals) else {
            continue;
        };
        let canonical = canonical_key(key);
        if !is_credential_key(&canonical) {
            continue;
        }

        let assignment_value = assignment_value(text, equals + 1);
        if matches!(assignment_value, "true" | "false" | "null") {
            continue;
        }
        if canonical == "hashedpassword" && assignment_value == "\"!\"" {
            continue;
        }
        if safe_nixos_nss_database_assignment(text, equals) {
            continue;
        }
        if is_credential_reference_key(&canonical)
            && (safe_runtime_secret_reference(assignment_value)
                || safe_public_account_database_reference(&canonical, assignment_value))
        {
            continue;
        }
        return true;
    }
    false
}

/// `system.nssDatabases.*` lists NSS *service module* names (`files`, `authd`,
/// `sss`, `himmelblau`), never credential material, but `passwd` trips
/// [`is_credential_key`]. Accept the whole option family whenever the value is
/// a list of bare service identifiers, optionally wrapped in a priority helper.
///
/// This deliberately does not pin one literal spelling. It used to accept only
/// `lib.mkOrder 490 [ "authd" ]`; when `cybex-authd.nix` dropped that wrapper
/// to fix an NSS lookup deadlock, every Blueprint build began failing this
/// check, and because a rejected job never reaches the local database it could
/// not be reported either -- Manage showed the builds queued forever. Any
/// literal password smuggled into the value is still caught by the modular
/// password hash and credential URL scans, which run over the same text.
fn safe_nixos_nss_database_assignment(text: &str, equals: usize) -> bool {
    let Some(option) = dotted_option_key(text, equals) else {
        return false;
    };
    let Some(database) = option.strip_prefix("system.nssDatabases.") else {
        return false;
    };
    if database.is_empty() || database.contains('.') {
        return false;
    }
    nss_service_list_value(text, equals)
}

/// Walk back from `=` over a full dotted NixOS option path. [`assignment_key`]
/// deliberately stops at `.` (it wants the leaf for credential matching), so
/// the option family needs its own reader.
fn dotted_option_key(text: &str, equals: usize) -> Option<&str> {
    let bytes = text.as_bytes();
    let mut end = equals;
    while end > 0 && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    let mut start = end;
    while start > 0
        && (bytes[start - 1].is_ascii_alphanumeric()
            || matches!(bytes[start - 1], b'_' | b'-' | b'.'))
    {
        start -= 1;
    }
    (start < end).then(|| &text[start..end])
}

/// Read the assignment value up to its terminating `;`, then check it is a
/// (possibly priority-wrapped) Nix list of bare NSS service names.
///
/// This reads to `;` rather than reusing [`assignment_value`], which also stops
/// at newlines: NSS database lists are routinely written across several lines.
fn nss_service_list_value(text: &str, equals: usize) -> bool {
    const MAX_NSS_ASSIGNMENT_BYTES: usize = 4096;

    let remainder = &text[equals + 1..];
    let bounded = &remainder[..remainder.len().min(MAX_NSS_ASSIGNMENT_BYTES)];
    let Some(terminator) = bounded.find(';') else {
        return false;
    };

    // Strip an optional priority wrapper. NixOS modules use these to order
    // themselves against other modules' NSS entries; they carry no value.
    let list = strip_nss_priority_wrapper(bounded[..terminator].trim());
    let Some(inner) = list
        .trim()
        .strip_prefix('[')
        .and_then(|list| list.strip_suffix(']'))
    else {
        return false;
    };
    nss_service_names_only(inner)
}

fn strip_nss_priority_wrapper(value: &str) -> &str {
    for prefix in ["lib.mkOrder", "mkOrder"] {
        if let Some(rest) = value.strip_prefix(prefix) {
            let rest = rest.trim_start();
            let digits = rest.len()
                - rest
                    .trim_start_matches(|ch: char| ch.is_ascii_digit())
                    .len();
            if digits > 0 {
                return &rest[digits..];
            }
        }
    }
    for prefix in ["lib.mkBefore", "mkBefore", "lib.mkAfter", "mkAfter"] {
        if let Some(rest) = value.strip_prefix(prefix) {
            return rest;
        }
    }
    value
}

/// The list body must be nothing but quoted bare service names. Whitespace is
/// skipped between entries but never allowed inside one, so a quoted phrase
/// does not pass as a service name. Quotes may be escaped when the module text
/// is itself nested inside a Nix string.
fn nss_service_names_only(inner: &str) -> bool {
    let mut rest = inner.trim();
    while !rest.is_empty() {
        let quote: &str = if rest.starts_with("\\\"") {
            "\\\""
        } else {
            "\""
        };
        let Some(after_open) = rest.strip_prefix(quote) else {
            return false;
        };
        let Some(close) = after_open.find(quote) else {
            return false;
        };
        let name = &after_open[..close];
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        {
            return false;
        }
        rest = after_open[close + quote.len()..].trim_start();
    }
    true
}

fn assignment_key(text: &str, equals: usize) -> Option<&str> {
    let bytes = text.as_bytes();
    let mut end = equals;
    while end > 0 && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    if end > 0 && matches!(bytes[end - 1], b'\'' | b'"') {
        let quote = bytes[end - 1];
        let start = bytes[..end - 1].iter().rposition(|byte| *byte == quote)?;
        let key = (start + 1 < end - 1).then_some(&text[start + 1..end - 1])?;
        // In shell tests, `"$variable" = value` is a comparison expression,
        // not an assignment. It cannot persist a credential and treating it
        // as a quoted attribute made the captured-home absolute-path guard
        // look like a second `passwd_file` assignment. A real quoted key such
        // as `"password" = value` does not begin with `$` and remains covered.
        if key.starts_with('$') {
            return None;
        }
        return Some(key);
    }
    let mut start = end;
    while start > 0
        && (bytes[start - 1].is_ascii_alphanumeric() || matches!(bytes[start - 1], b'_' | b'-'))
    {
        start -= 1;
    }
    // Manage embeds shell helpers in a JSON-escaped Nix string. A logical
    // newline is therefore written as `\n`, and the old reader accidentally
    // treated that `n` as the first character of the following assignment.
    if start > 0
        && start + 1 < end
        && bytes[start - 1] == b'\\'
        && matches!(bytes[start], b'n' | b'r')
    {
        start += 1;
    }
    (start < end).then_some(&text[start..end])
}

fn assignment_value(text: &str, start: usize) -> &str {
    let remainder = text[start..].trim_start();
    let bytes = remainder.as_bytes();
    let mut end = remainder.len();
    let mut index = 0usize;
    while index < bytes.len() {
        if matches!(bytes[index], b';' | b'\n' | b'\r' | b',') {
            end = index;
            break;
        }
        if bytes[index] == b'\\' {
            let escape_start = index;
            while index < bytes.len() && bytes[index] == b'\\' {
                index += 1;
            }
            if (index - escape_start) % 2 == 1
                && bytes
                    .get(index)
                    .is_some_and(|byte| matches!(byte, b'n' | b'r'))
            {
                end = escape_start;
                break;
            }
            continue;
        }
        index += 1;
    }
    remainder[..end].trim()
}

/// `/etc/passwd` is the public NSS account database, not the protected shadow
/// database. Older Manage revisions embed a captured-home helper whose third
/// argument defaults to this path. Accept only those exact spellings so the
/// historical revisions remain buildable without allowing `/etc/shadow`, an
/// arbitrary file, or a literal credential value.
fn safe_public_account_database_reference(canonical_key: &str, value: &str) -> bool {
    canonical_key == "passwdfile"
        && matches!(
            value.trim(),
            "/etc/passwd" | "\"/etc/passwd\"" | "${3:-/etc/passwd}" | "\\${3:-/etc/passwd}"
        )
}

fn json_credential_value_is_safe_reference(canonical_key: &str, value: &Value) -> bool {
    // Boolean policy options such as `wheelNeedsPassword` describe behavior,
    // not credential material. Numeric and string literals remain protected.
    if value.is_boolean() || value.is_null() {
        return true;
    }
    if canonical_key == "hashedpassword" && value.as_str() == Some("!") {
        return true;
    }
    is_credential_reference_key(canonical_key)
        && value.as_str().is_some_and(safe_runtime_secret_reference)
}

fn contains_credential_url(text: &str) -> bool {
    text.split(|ch: char| {
        ch.is_whitespace()
            || matches!(
                ch,
                '\'' | '"' | '`' | '(' | ')' | '[' | ']' | '{' | '}' | ';' | ','
            )
    })
    .filter(|candidate| candidate.contains("://"))
    .any(|candidate| {
        let candidate = candidate.trim_matches(|ch: char| matches!(ch, '.' | ':' | '!' | '?'));
        if raw_url_authority_contains_percent(candidate) {
            return true;
        }
        let Ok(url) = reqwest::Url::parse(candidate) else {
            // A URL-shaped value with explicit authority userinfo is unsafe
            // even when another malformed component prevents full parsing.
            return candidate
                .split_once("://")
                .and_then(|(_, rest)| rest.split(['/', '?', '#']).next())
                .is_some_and(|authority| authority.contains('@'));
        };
        !url.username().is_empty()
            || url.password().is_some()
            || url
                .path_segments()
                .into_iter()
                .flatten()
                .any(url_component_contains_protected_material)
            || url.query_pairs().any(|(key, value)| {
                url_component_contains_protected_material(&key)
                    || url_component_contains_protected_material(&value)
            })
            || url
                .fragment()
                .is_some_and(url_component_contains_protected_material)
    })
}

fn raw_url_authority_contains_percent(value: &str) -> bool {
    let Some((_, rest)) = value.split_once("://") else {
        return false;
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    rest[..end].contains('%')
}

fn url_component_contains_protected_material(value: &str) -> bool {
    let decoded = percent_decode_ascii_url_component(value);
    if contains_modular_password_hash(&decoded) {
        return true;
    }
    let lower = decoded.to_ascii_lowercase();
    let canonical = canonical_key(&lower);
    matches!(
        canonical.as_str(),
        "token"
            | "accesstoken"
            | "refreshtoken"
            | "sessiontoken"
            | "bearertoken"
            | "auth"
            | "authorization"
            | "password"
            | "passwd"
            | "passphrase"
            | "psk"
            | "wifipsk"
            | "secret"
            | "clientsecret"
            | "secretaccesskey"
            | "accesskeyid"
            | "apikey"
            | "key"
            | "privatekey"
            | "credential"
            | "credentials"
            | "cookie"
            | "sessionid"
            | "jwt"
            | "sig"
            | "xamzsignature"
            | "xgoogsignature"
            | "sharedaccesssignature"
    ) || lower
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .any(|part| {
            matches!(
                part,
                "authorization"
                    | "apikey"
                    | "apitoken"
                    | "accesstoken"
                    | "credential"
                    | "credentials"
                    | "idtoken"
                    | "key"
                    | "password"
                    | "passwd"
                    | "refreshtoken"
                    | "secret"
                    | "token"
            )
        })
}

fn percent_decode_ascii_url_component(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(high), Some(low)) = (
                ascii_hex_digit_value(bytes[index + 1]),
                ascii_hex_digit_value(bytes[index + 2]),
            ) {
                decoded.push((high << 4) | low);
                index += 3;
                continue;
            }
        }
        decoded.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

fn ascii_hex_digit_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn is_credential_key(canonical: &str) -> bool {
    [
        "password",
        "passwd",
        "passwordhash",
        "hashedpassword",
        "passphrase",
        "psk",
        "wifipsk",
        "token",
        "bearertoken",
        "sessiontoken",
        "apikey",
        "secret",
        "clientsecret",
        "secretaccesskey",
        "accesskeyid",
        "privatekey",
        "authorization",
        "credential",
        "credentials",
        "cookie",
        "sessionid",
        "jwt",
    ]
    .iter()
    .any(|suffix| canonical.ends_with(suffix))
        || is_credential_reference_key(canonical)
}

fn is_credential_reference_key(canonical: &str) -> bool {
    let references_secret = [
        "password",
        "passwd",
        "token",
        "apikey",
        "secret",
        "privatekey",
        "credential",
    ]
    .iter()
    .any(|part| canonical.contains(part));
    references_secret
        && ["file", "path", "ref", "reference"]
            .iter()
            .any(|suffix| canonical.ends_with(suffix))
}

fn safe_runtime_secret_reference(value: &str) -> bool {
    let value = value.trim();
    let value = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(value);
    if value.is_empty()
        || value.contains("..")
        || value
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace())
    {
        return false;
    }
    // Device-local account hashes use a deterministic public reference, but
    // its derivation can only be proven from the complete installer-target
    // expected-state contract. That exact exemption is handled before the
    // generic scanner; never accept this path shape on syntax alone here.
    if value.starts_with(CYBEX_LOCAL_ACCOUNT_SECRET_PREFIX) {
        return false;
    }
    if [
        "/run/cybex/secrets/",
        "/run/secrets/",
        "/run/agenix/",
        "/run/credentials/",
    ]
    .iter()
    .any(|prefix| value.starts_with(prefix) && value.len() > prefix.len())
    {
        return true;
    }
    ["config.sops.secrets.", "config.age.secrets."]
        .iter()
        .any(|prefix| value.starts_with(prefix) && value.ends_with(".path"))
}

fn canonical_key(value: &str) -> String {
    value
        .bytes()
        .filter(|byte| byte.is_ascii_alphanumeric())
        .map(|byte| byte.to_ascii_lowercase() as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const SENTINEL: &str = "CYBEX_JAMES_PROTECTED_SENTINEL_7f922a";
    const PASSWORD_HASH: &str = "$6$rounds=5000$abcdefghijklmnop$uHL2DmwkR2iK6s.wDbxLW3GxvjJT7qW2rEHemZz3oMlKlfj8JwHc99.FNZrTO4drUslZ0MRyYkBDumQxKdL8q/";

    fn build_spec(generated_nix: &str, desktop_module_nix: &str, expected_state: Value) -> Value {
        json!({
            "schema_version": 1,
            "artifact_type": "nixos_closure",
            "target": "blueprint",
            "system": "x86_64-linux",
            "input_revision": "revision",
            "input_config_hash": "a".repeat(64),
            "build_input": {
                "kind": "blueprint_nixos_module",
                "generated_nix": generated_nix,
                "desktop_module_nix": desktop_module_nix,
                "expected_state": expected_state
            }
        })
    }

    fn installer_target_local_account_spec(secret_ref: &str) -> Value {
        let revision = Uuid::parse_str("11111111-2222-4333-8444-555555555555").unwrap();
        let profile_generation = "b".repeat(64);
        let derived_ref = local_account_secret_ref(revision, &profile_generation, "student");
        let selected_ref = if secret_ref == "derived" {
            derived_ref
        } else {
            secret_ref.to_string()
        };
        let mut spec = build_spec(
            &format!(
                "{{ ... }}:\n{{\n  # Dynamic local-account profile overlay\n  users.users.\"student\" = {{\n    isNormalUser = true;\n    description = \"Shared Student\";\n    extraGroups = [ \"audio\" \"networkmanager\" \"video\" ];\n    hashedPasswordFile = \"{CYBEX_LOCAL_ACCOUNT_SECRET_PREFIX}{selected_ref}\";\n  }};\n}}\n"
            ),
            "{ ... }:\n{\n}\n",
            json!({
                "schema": EXPECTED_STATE_V2_SCHEMA,
                "compiler_version": 2,
                "deployment": {
                    "blueprint_revision_id": revision,
                    "local_account_profile_generation_sha256": profile_generation,
                },
                "checks": [{
                    "id": "identity.local-account.inventory",
                    "kind": "local-account-inventory",
                    "expected": {
                        "accounts": [{
                            "username": "student",
                            "display_name": "Shared Student",
                            "admin": false,
                            "groups": ["audio", "networkmanager", "video"],
                        }],
                    },
                }, {
                    "id": "identity.local-account.student.password",
                    "kind": LOCAL_ACCOUNT_PASSWORD_HASH_CHECK_KIND,
                    "expected": {
                        "username": "student",
                        "password_secret_ref": selected_ref,
                    },
                }],
            }),
        );
        spec["blueprint_revision_id"] = json!(revision);
        spec["target"] = json!("installer_target");
        spec["build_input"]["kind"] = json!(INSTALLER_TARGET_BUILD_INPUT_KIND);
        spec
    }

    #[test]
    fn rejects_protected_values_from_each_reusable_build_input_surface() {
        let generated = build_spec(
            &format!("{{ ... }}: {{ users.users.alice.hashedPassword = \"{SENTINEL}\"; }}"),
            "{ ... }: {}",
            json!({"schema": "cybex.blueprint.expected-state.v2"}),
        );
        let generated_error = validate_build_spec(&generated).unwrap_err().to_string();
        assert!(!generated_error.contains(SENTINEL));

        let desktop = build_spec(
            "{ ... }: {}",
            &format!("{{ ... }}: {{ services.example.apiToken = \"{SENTINEL}\"; }}"),
            json!({"schema": "cybex.blueprint.expected-state.v2"}),
        );
        let desktop_error = validate_build_spec(&desktop).unwrap_err().to_string();
        assert!(!desktop_error.contains(SENTINEL));

        let quoted_attribute = build_spec(
            &format!("{{ ... }}: {{ users.users.alice.\"hashedPassword\" = \"{SENTINEL}\"; }}"),
            "{ ... }: {}",
            json!({"schema": "cybex.blueprint.expected-state.v2"}),
        );
        let quoted_error = validate_build_spec(&quoted_attribute)
            .unwrap_err()
            .to_string();
        assert!(!quoted_error.contains(SENTINEL));

        let expected_state = build_spec(
            "{ ... }: {}",
            "{ ... }: {}",
            json!({
                "schema": "cybex.blueprint.expected-state.v2",
                "activation_secrets": {"local_account_password_hashes": {"alice": SENTINEL}}
            }),
        );
        let expected_error = validate_build_spec(&expected_state)
            .unwrap_err()
            .to_string();
        assert!(!expected_error.contains(SENTINEL));
    }

    #[test]
    fn rejects_bare_modular_hashes_and_credential_cache_metadata() {
        let spec = build_spec(
            &format!("{{ ... }}: {{ environment.etc.example.text = \"{PASSWORD_HASH}\"; }}"),
            "{ ... }: {}",
            json!({"schema": "cybex.blueprint.expected-state.v2"}),
        );
        let error = validate_build_spec(&spec).unwrap_err().to_string();
        assert!(!error.contains(PASSWORD_HASH));

        let metadata = json!({"builder": {"access_token": SENTINEL}});
        let error = validate_cache_metadata(&metadata).unwrap_err().to_string();
        assert!(!error.contains(SENTINEL));
    }

    #[test]
    fn rejects_common_cloud_wifi_and_session_credentials_before_persistence() {
        for (key, value) in [
            ("wifi_psk", "correct horse battery staple"),
            ("passphrase", "private phrase"),
            ("secret_access_key", "cloud-secret"),
            ("access_key_id", "AKIAEXAMPLE"),
            ("session_token", "session-secret"),
            ("cookie", "sid=protected"),
            ("jwt", "eyJhbGciOiJub25lIn0.payload.signature"),
        ] {
            let mut spec = build_spec(
                "{ ... }: {}",
                "{ ... }: {}",
                json!({"schema": "cybex.blueprint.expected-state.v2"}),
            );
            spec.as_object_mut()
                .unwrap()
                .insert(key.into(), Value::String(value.into()));
            let error = validate_build_spec(&spec).unwrap_err().to_string();
            assert!(!error.contains(value));
        }

        for url in [
            "https://s3.example/object?X-Amz-Signature=protected",
            "https://storage.example/object?X-Goog-Signature=protected",
            "https://blob.example/object?sig=protected",
        ] {
            let mut spec = build_spec(
                "{ ... }: {}",
                "{ ... }: {}",
                json!({"schema": "cybex.blueprint.expected-state.v2"}),
            );
            spec.as_object_mut()
                .unwrap()
                .insert("source_url".into(), Value::String(url.into()));
            assert!(validate_build_spec(&spec).is_err());
        }
    }

    #[test]
    fn hexadecimal_literals_are_not_accepted_as_runtime_secret_references() {
        let sentinel = "d34db33fd34db33fd34db33fd34db33fd34db33fd34db33fd34db33fd34db33f";
        let mut spec = build_spec(
            "{ ... }: {}",
            "{ ... }: {}",
            json!({"schema": "cybex.blueprint.expected-state.v2"}),
        );
        spec.as_object_mut()
            .unwrap()
            .insert("api_token_ref".into(), Value::String(sentinel.into()));
        let error = validate_build_spec(&spec).unwrap_err().to_string();
        assert!(!error.contains(sentinel));
    }

    #[test]
    fn allows_locked_accounts_and_generic_runtime_secret_paths() {
        let spec = build_spec(
            r#"{ ... }: {
              users.users.disabled.hashedPassword = "!";
              users.users.alice.hashedPasswordFile = "/run/secrets/alice-password-hash";
              services.example.passwordFile = config.sops.secrets.example.path;
            }"#,
            "{ ... }: {}",
            json!({"schema": "cybex.blueprint.expected-state.v2"}),
        );

        validate_build_spec(&spec).unwrap();
    }

    #[test]
    fn allows_any_nixos_nss_database_service_list() {
        for desktop_module_nix in [
            // The wrapped form, and the bare form cybex-authd.nix moved to
            // when ordering authd ahead of files deadlocked NSS lookups.
            r#"{ ... }: {
              system.nssDatabases.passwd = lib.mkOrder 490 [ "authd" ];
            }"#,
            r#"{ ... }: {
              system.nssDatabases.passwd = [ "authd" ];
            }"#,
            r#"{ ... }: {
              system.nssDatabases.passwd = lib.mkOrder 1501 [ "himmelblau" ];
            }"#,
            r#"{ ... }: {
              system.nssDatabases.passwd = mkAfter [ "sss" ];
              system.nssDatabases.passwd = lib.mkBefore [ "files" "authd" ];
            }"#,
            // Lists routinely wrap across lines.
            r#"{ ... }: {
              system.nssDatabases.passwd = [
                "files"
                "authd"
              ];
            }"#,
            // The module text is itself nested inside a Nix string.
            r#"{ ... }: {
              embedded = "system.nssDatabases.passwd = [ \"authd\" ];";
            }"#,
        ] {
            validate_desktop_module_nix(desktop_module_nix).unwrap();
        }

        for rejected in [
            // Only the real option family is exempt.
            r#"services.example.passwd = lib.mkOrder 490 [ "authd" ];"#,
            r#"passwd = lib.mkOrder 490 [ "authd" ];"#,
            r#"system.nssDatabases.deeper.passwd = [ "authd" ];"#,
            // ... and only when the value really is a service-name list.
            r#"system.nssDatabases.passwd = "literal-secret";"#,
            r#"system.nssDatabases.passwd = [ "authd" "sneaky secret" ];"#,
            r#"system.nssDatabases.passwd = builtins.readFile "literal-secret";"#,
        ] {
            let error = validate_desktop_module_nix(rejected)
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("literal credential assignment"),
                "{rejected}"
            );
            assert!(!error.contains("literal-secret"));
        }
    }

    #[test]
    fn nss_database_exemption_still_catches_embedded_password_hashes() {
        // The exemption only silences the credential-assignment scan; the
        // hash, activation-secret, and credential-URL scans still cover the
        // same text, so the widened rule cannot become a smuggling route.
        let error = validate_desktop_module_nix(&format!(
            r#"system.nssDatabases.passwd = [ "authd" ]; # {PASSWORD_HASH}"#
        ))
        .unwrap_err()
        .to_string();
        assert!(error.contains("modular password hash"));

        let error = validate_desktop_module_nix(
            r#"system.nssDatabases.passwd = [ "authd" ]; # https://u:pw@example.test/x"#,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("credential-bearing URL"));
    }

    #[test]
    fn generic_builds_reject_manage_local_account_runtime_secret_references() {
        let secret_ref = "a".repeat(64);
        let managed_path = format!("{CYBEX_LOCAL_ACCOUNT_SECRET_PREFIX}{secret_ref}");
        let spec = build_spec(
            &format!("{{ ... }}: {{ users.users.alice.hashedPasswordFile = \"{managed_path}\"; }}"),
            "{ ... }: { users.users.disabled.hashedPassword = \"!\"; }",
            json!({"schema": "cybex.blueprint.expected-state.v2"}),
        );
        assert!(validate_build_spec(&spec).is_err());

        for rejected_path in [
            format!("{CYBEX_LOCAL_ACCOUNT_SECRET_PREFIX}short"),
            format!("{CYBEX_LOCAL_ACCOUNT_SECRET_PREFIX}{}", "A".repeat(64)),
            format!("{CYBEX_LOCAL_ACCOUNT_SECRET_PREFIX}{secret_ref}/extra"),
            format!("{CYBEX_LOCAL_ACCOUNT_SECRET_PREFIX}../{secret_ref}"),
            format!("/var/lib/cybex-agent/secrets/other/{secret_ref}"),
        ] {
            let rejected = build_spec(
                &format!(
                    "{{ ... }}: {{ users.users.alice.hashedPasswordFile = \"{rejected_path}\"; }}"
                ),
                "{ ... }: {}",
                json!({"schema": "cybex.blueprint.expected-state.v2"}),
            );
            let error = validate_build_spec(&rejected).unwrap_err().to_string();
            assert!(!error.contains(&rejected_path));
        }
    }

    #[test]
    fn installer_target_allows_only_exact_public_local_account_secret_refs() {
        let spec = installer_target_local_account_spec("derived");
        let secret_ref =
            spec["build_input"]["expected_state"]["checks"][1]["expected"]["password_secret_ref"]
                .as_str()
                .unwrap()
                .to_string();
        validate_build_spec(&spec).unwrap();
        validate_installer_target_expected_state(&spec["build_input"]["expected_state"]).unwrap();

        let mut reusable = spec.clone();
        reusable["build_input"]["kind"] = json!("blueprint_nixos_module");
        let error = validate_build_spec(&reusable).unwrap_err().to_string();
        assert!(error.contains("protected material"));
        assert!(!error.contains(&secret_ref));

        for rejected_ref in [
            "short".to_string(),
            "A".repeat(64),
            format!("{secret_ref}0"),
            "a".repeat(64),
        ] {
            let rejected = installer_target_local_account_spec(&rejected_ref);
            let error = validate_build_spec(&rejected).unwrap_err().to_string();
            assert!(error.contains("protected material"));
            assert!(!error.contains(&rejected_ref));
        }

        let mut wrong_id = spec.clone();
        wrong_id["build_input"]["expected_state"]["checks"][0]["id"] =
            json!("identity.local-account.other.password");
        assert!(validate_build_spec(&wrong_id).is_err());

        let mut mismatched_path = spec.clone();
        mismatched_path["build_input"]["expected_state"]["checks"][1]["expected"]["password_secret_ref"] =
            json!("b".repeat(64));
        assert!(validate_build_spec(&mismatched_path).is_err());

        let mut extra_field = spec.clone();
        extra_field["build_input"]["expected_state"]["checks"][1]["expected"]["extra"] =
            json!(true);
        assert!(validate_build_spec(&extra_field).is_err());

        let mut protected = spec;
        protected["activation_secrets"] = json!({"student": PASSWORD_HASH});
        let error = validate_build_spec(&protected).unwrap_err().to_string();
        assert!(!error.contains(PASSWORD_HASH));
    }

    #[test]
    fn installer_target_accepts_canonical_locked_admin_with_local_account() {
        let mut spec = installer_target_local_account_spec("derived");
        let generated = spec["build_input"]["generated_nix"]
            .as_str()
            .unwrap()
            .replacen(
                "  # Dynamic local-account profile overlay\n",
                "  users.users.cybex-admin = {\n    isNormalUser = true;\n    description = \"Cybex break-glass administrator\";\n    extraGroups = [ \"wheel\" \"networkmanager\" \"video\" \"audio\" ];\n    hashedPassword = \"!\";\n  };\n  # Dynamic local-account profile overlay\n",
                1,
            );
        spec["build_input"]["generated_nix"] = json!(generated);

        validate_build_spec(&spec).unwrap();
    }

    #[test]
    fn installer_target_kind_and_target_are_bidirectionally_bound() {
        let spec = installer_target_local_account_spec("derived");

        let mut installer_kind_on_reusable_target = spec.clone();
        installer_kind_on_reusable_target["target"] = json!("blueprint");
        assert!(validate_build_spec(&installer_kind_on_reusable_target).is_err());

        let mut reusable_kind_on_installer_target = spec;
        reusable_kind_on_installer_target["build_input"]["kind"] = json!("blueprint_nixos_module");
        assert!(validate_build_spec(&reusable_kind_on_installer_target).is_err());
    }

    #[test]
    fn installer_target_account_overlay_must_be_live_and_unshadowed() {
        let spec = installer_target_local_account_spec("derived");
        validate_build_spec(&spec).unwrap();
        let canonical = spec["build_input"]["generated_nix"].as_str().unwrap();

        let mut commented = spec.clone();
        commented["build_input"]["generated_nix"] =
            json!(format!("/*{canonical}*/\n{{ ... }}: {{}}"));
        assert!(validate_build_spec(&commented).is_err());

        let mut multiline_string = spec.clone();
        multiline_string["build_input"]["generated_nix"] =
            json!(format!("{{ ... }}: {{ text = ''\n{canonical}\n''; }}"));
        assert!(validate_build_spec(&multiline_string).is_err());

        let mut unused_binding = spec.clone();
        unused_binding["build_input"]["generated_nix"] = json!(format!(
            "{{ ... }}:\nlet ignored = {{\n{}\n}}; in {{}}\n",
            canonical
                .strip_prefix("{ ... }:\n{\n")
                .and_then(|value| value.strip_suffix("}\n"))
                .unwrap()
        ));
        assert!(validate_build_spec(&unused_binding).is_err());

        let mut ignored_argument = spec.clone();
        ignored_argument["build_input"]["generated_nix"] = json!(format!(
            "{{ ... }}:\n(_: {{}}) {{\n{}\n}}\n",
            canonical
                .strip_prefix("{ ... }:\n{\n")
                .and_then(|value| value.strip_suffix("}\n"))
                .unwrap()
        ));
        assert!(validate_build_spec(&ignored_argument).is_err());

        let mut nested_let_binding = spec.clone();
        nested_let_binding["build_input"]["generated_nix"] = json!(format!(
            "{{ ... }}:\n{{\n  value = let\n{}\n  in null;\n}}\n",
            canonical
                .strip_prefix("{ ... }:\n{\n")
                .and_then(|value| value.strip_suffix("}\n"))
                .unwrap()
        ));
        assert!(validate_build_spec(&nested_let_binding).is_err());

        for override_nix in [
            "  users.users = lib.mkForce {};\n",
            "  users.users = lib.mkForce { };\n",
            "  users = lib.mkForce {};\n",
            "  \"users\".\"users\".\"student\".shell = pkgs.bash;\n",
            "  ${\"users\"}.${\"users\"}.${\"student\"}.shell = pkgs.bash;\n",
            "  ${\"users\"}.${\"users\"}.root.openssh.authorizedKeys.keys = [ \"ssh-ed25519 AAAA\" ];\n",
            "  ${u}.${u}.root.openssh.authorizedKeys.keys = [ \"ssh-ed25519 AAAA\" ];\n",
            "  users.users.\"student\".openssh.authorizedKeys.keys = [ \"ssh-ed25519 AAAA\" ];\n",
            "  users.users.cybex-admin.openssh.authorizedKeys.keys = [ \"ssh-ed25519 AAAA\" ];\n",
            "users.users.cybex-admin = { isNormalUser = true; extraGroups = [ \"wheel\" ]; openssh.authorizedKeys.keys = [ \"ssh-ed25519 AAAA\" ]; };\n",
            "  \"users\".\"users\".cybex-admin = { isNormalUser = true; extraGroups = [ \"wheel\" ]; };\n",
            "  users.users.\"intruder\" = { isNormalUser = true; };\n",
            "  users.extraUsers.\"student\".hashedPasswordFile = lib.mkForce \"/run/secrets/override\";\n",
            "  \"users\".\"extraUsers\".\"student\".hashedPasswordFile = lib.mkForce \"/run/secrets/override\";\n",
            "  let accountRoot = \"us\" + \"ers\"; in \"${accountRoot}\".\"${accountRoot}\".\"${\"stu\" + \"dent\"}\".hashedPasswordFile = lib.mkForce \"/run/secrets/override\";\n",
            "  // (builtins.fromJSON ''{\"users\":{\"users\":{\"student\":{\"hashedPasswordFile\":\"/run/secrets/override\"}}}}'')\n",
            "  // (builtins.fromTOML ''[users.users.student]\nhashedPasswordFile = \"/run/secrets/override\"\n'')\n",
            "  builtins.removeAttrs { users.users.\"student\" = {}; } [ \"users\" ]\n",
            "  lib.filterAttrs (name: _: name != \"users\") { users.users.\"student\" = {}; }\n",
            "  imports = [ ({ ... }: let set = name: value: builtins.listToAttrs [ { inherit name value; } ]; in set \"users\" (set \"users\" (set \"root\" {}))) ];\n",
        ] {
            let mut overridden = spec.clone();
            let generated = overridden["build_input"]["generated_nix"]
                .as_str()
                .unwrap()
                .replacen("}\n", &format!("{override_nix}}}\n"), 1);
            overridden["build_input"]["generated_nix"] = json!(generated);
            assert!(validate_build_spec(&overridden).is_err(), "{override_nix}");
        }

        let mut wrong_revision = spec;
        wrong_revision["blueprint_revision_id"] = json!("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee");
        assert!(validate_build_spec(&wrong_revision).is_err());
    }

    #[test]
    fn installer_target_scans_non_account_text_before_persistence() {
        let mut spec = installer_target_local_account_spec("derived");
        let generated = spec["build_input"]["generated_nix"]
            .as_str()
            .unwrap()
            .replacen(
                "}\n",
                &format!(
                    "  environment.etc.unsafe.text = {};\n}}\n",
                    json_string(PASSWORD_HASH)
                ),
                1,
            );
        spec["build_input"]["generated_nix"] = json!(generated);
        let error = validate_build_spec(&spec).unwrap_err().to_string();
        assert!(error.contains("protected material"));
        assert!(!error.contains(PASSWORD_HASH));

        let mut token = installer_target_local_account_spec("derived");
        let generated = token["build_input"]["generated_nix"]
            .as_str()
            .unwrap()
            .replacen(
                "}\n",
                "  services.example.api_token = \"credential-sentinel\";\n}\n",
                1,
            );
        token["build_input"]["generated_nix"] = json!(generated);
        assert!(validate_build_spec(&token).is_err());
    }

    #[test]
    fn installer_target_without_accounts_rejects_unmanaged_users() {
        let revision = Uuid::parse_str("11111111-2222-4333-8444-555555555555").unwrap();
        let mut spec = build_spec(
            "{ ... }:\n{\n}\n",
            "{ ... }: {}",
            json!({
                "schema": EXPECTED_STATE_V2_SCHEMA,
                "compiler_version": 2,
                "deployment": {"blueprint_revision_id": revision},
                "checks": [{
                    "id": "identity.local-account.inventory",
                    "kind": "local-account-inventory",
                    "expected": {"accounts": []},
                }],
            }),
        );
        spec["blueprint_revision_id"] = json!(revision);
        spec["target"] = json!("installer_target");
        spec["build_input"]["kind"] = json!(INSTALLER_TARGET_BUILD_INPUT_KIND);
        validate_build_spec(&spec).unwrap();

        spec["build_input"]["generated_nix"] =
            json!("{ ... }: { users.users.\"intruder\" = { isNormalUser = true; }; }");
        assert!(validate_build_spec(&spec).is_err());
    }

    #[test]
    fn installer_target_rejects_user_definitions_from_every_other_module() {
        for hostile in [
            "{ ... }: { users.users.root.openssh.authorizedKeys.keys = [ \"ssh-ed25519 AAAA\" ]; }",
            "{ ... }: { \"users\".\"users\".root.shell = /bin/sh; }",
            "{ ... }: { users.extraUsers.root.shell = /bin/sh; }",
            "{ ... }: let set = name: value: builtins.listToAttrs [ { inherit name value; } ]; in set \"users\" (set \"users\" {});",
            "{ ... }: { imports = [ ({ ... }: {}) ]; }",
            "{ ... }: { value = lib.setAttrByPath [ \"users\" \"users\" \"root\" ] {}; }",
        ] {
            let error = validate_installer_target_non_blueprint_module(
                "build_spec.build_input.target_module_nix",
                hostile,
            )
            .unwrap_err()
            .to_string();
            assert!(error.contains("protected material"));
            assert!(!error.contains("ssh-ed25519"));
        }

        validate_installer_target_non_blueprint_module(
            "build_spec.build_input.target_module_nix",
            "{ lib, ... }: { networking.hostName = lib.mkDefault \"workstation\"; }",
        )
        .unwrap();
        validate_installer_target_non_blueprint_module(
            "build_spec.build_input.target_module_nix",
            "{ ... }: { cybex.agent.organizationSlug = \"users\"; }",
        )
        .unwrap();
    }

    #[test]
    fn allows_only_the_public_passwd_database_reference() {
        for generated_nix in [
            "passwd_file = /etc/passwd;",
            "passwd_file = \"/etc/passwd\";",
            "passwd_file=${3:-/etc/passwd}\n",
            "text = \"#!/usr/bin/env bash\\npasswd_file=\\${3:-/etc/passwd}\\nhome_root=\\${4:-/home}\\n\";",
            "text = \"passwd_file=\\${3:-/etc/passwd}\\n[[ \\\"$state_dir\\\" = /* && \\\"$passwd_file\\\" = /* && \\\"$home_root\\\" = /* ]] || exit 1\\n\";",
        ] {
            validate_generated_nix(generated_nix).unwrap();
        }

        for generated_nix in [
            "passwd_file = /etc/shadow;",
            "passwd_file = /tmp/passwd;",
            "passwd_file=${3:-/etc/shadow}\n",
            "text = \"passwd_file=\\${3:-/etc/shadow}\\n\";",
        ] {
            let error = validate_generated_nix(generated_nix)
                .unwrap_err()
                .to_string();
            assert!(error.contains("literal credential assignment"));
        }
    }

    #[test]
    fn rejects_cybex_activation_secret_references_from_reusable_text() {
        for reference in [
            "/run/cybex/activation-secrets/revision/alice",
            "/run/cybex/activation_secrets/revision/alice",
            "/run/cybex/activationSecrets/revision/alice",
        ] {
            let spec = build_spec(
                &format!("{{ ... }}: {{ environment.variables.RUNTIME_PATH = \"{reference}\"; }}"),
                "{ ... }: {}",
                json!({"schema": "cybex.blueprint.expected-state.v2"}),
            );
            let error = validate_build_spec(&spec).unwrap_err().to_string();
            assert!(error.contains("activation secrets"));
            assert!(!error.contains(reference));
        }
    }

    #[test]
    fn allows_boolean_password_policy_but_rejects_credential_urls() {
        let policy = build_spec(
            r#"{ ... }: {
              security.sudo.wheelNeedsPassword = true;
              services.openssh.settings.PasswordAuthentication = false;
            }"#,
            "{ ... }: {}",
            json!({
                "schema": "cybex.blueprint.expected-state.v2",
                "wheel_needs_password": true
            }),
        );
        validate_build_spec(&policy).unwrap();

        let credential_sentinel = "credential-sentinel-7f922a";
        for credential_url in [
            &format!("https://alice:{credential_sentinel}@example.invalid/source.tar.gz"),
            &format!("https://example.invalid/source.tar.gz?access_token={credential_sentinel}"),
            &format!("https://example.invalid/private/secret/{credential_sentinel}"),
            &format!("https://example.invalid/private/%73ecret/{credential_sentinel}"),
            &format!("https://example.invalid/source.tar.gz#authorization={credential_sentinel}"),
            &format!("https://example.invalid/source.tar.gz#access%5Ftoken={credential_sentinel}"),
            &format!("https://alice%40example.invalid/source.tar.gz#{credential_sentinel}"),
        ] {
            let spec = build_spec(
                &format!(
                    "{{ ... }}: {{ environment.variables.SOURCE_URL = \"{credential_url}\"; }}"
                ),
                "{ ... }: {}",
                json!({"schema": "cybex.blueprint.expected-state.v2"}),
            );
            let error = validate_build_spec(&spec).unwrap_err().to_string();
            assert!(!error.contains(credential_sentinel));
        }

        let public_source = build_spec(
            r#"{ ... }: {
              environment.variables.SOURCE_URL = "https://example.invalid/releases/tokenizer/source.tar.gz#v1.0";
            }"#,
            "{ ... }: {}",
            json!({"schema": "cybex.blueprint.expected-state.v2"}),
        );
        validate_build_spec(&public_source).unwrap();
    }
}
