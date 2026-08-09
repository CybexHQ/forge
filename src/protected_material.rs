use std::{error::Error, fmt};

use serde_json::Value;

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
    if value
        .strip_prefix(CYBEX_LOCAL_ACCOUNT_SECRET_PREFIX)
        .is_some_and(|secret_ref| {
            secret_ref.len() == 64
                && secret_ref
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
    {
        return true;
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

    const SENTINEL: &str = "CYBEX_FORGE_PROTECTED_SENTINEL_7f922a";
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
    fn allows_only_exact_manage_local_account_runtime_secret_references() {
        let secret_ref = "a".repeat(64);
        let managed_path = format!("{CYBEX_LOCAL_ACCOUNT_SECRET_PREFIX}{secret_ref}");
        let spec = build_spec(
            &format!("{{ ... }}: {{ users.users.alice.hashedPasswordFile = \"{managed_path}\"; }}"),
            "{ ... }: { users.users.disabled.hashedPassword = \"!\"; }",
            json!({"schema": "cybex.blueprint.expected-state.v2"}),
        );
        validate_build_spec(&spec).unwrap();

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
