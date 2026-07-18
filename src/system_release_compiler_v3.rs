use std::collections::{BTreeMap, BTreeSet};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

pub const PROJECTION_SCHEMA: &str = "cybex.system-release-blueprint-projection.v3";
pub const PROJECTION_REVISION: &str = "cybex-system-release-blueprint-projection-v3";
pub const COMPILER_VERSION: &str = "cybex-system-release-compiler-v3";
pub const TYPED_CONFIG_SCHEMA: &str = "cybex.system-release-compiler-input.v3";
pub const ASSET_MANIFEST_SCHEMA: &str = "cybex.blueprint-assets.v1";
pub const EXTENSION_MANIFEST_SCHEMA: &str = "cybex.blueprint-extensions.v1";

const MAX_SOURCE_BYTES: usize = 1024 * 1024;
const MAX_VALUES: usize = 250_000;
const MAX_DEPTH: usize = 64;
const MAX_APPLICATIONS: usize = 100;
const MAX_LIST_ITEMS: usize = 512;
const MAX_ASSETS: usize = 160;
const MAX_EXTENSIONS: usize = 32;
const MAX_EXTENSION_TOTAL_BYTES: u64 = 8 * 1024 * 1024;
const MAX_ASSET_BYTES: u64 = 1024 * 1024;
const MAX_ASSET_TOTAL_BYTES: u64 = 24 * 1024 * 1024;

const SETTING_FIELDS: &[&str] = &[
    "application_mode",
    "captured",
    "hint",
    "kind",
    "label",
    "locked",
    "required",
    "source",
    "source_user",
    "target_scope",
    "value",
];

const LIST_SECTION_FIELDS: &[&str] = &["capture_authoritative", "icon", "items", "policy", "title"];

const LIST_ITEM_FIELDS: &[&str] = &[
    "description",
    "homepage",
    "icon",
    "icon_available",
    "id",
    "label",
    "license",
    "locked",
    "meta",
    "package_ref",
    "package_source",
    "platforms",
    "removed",
    "required",
    "search_branch",
    "source",
    "unfree",
    "version",
];

const CAPTURE_ASSET_FIELDS: &[&str] = &[
    "application_mode",
    "category",
    "content_base64",
    "logical_path",
    "mime_type",
    "sha256",
    "size_bytes",
    "target_scope",
];

const EXTENSION_FIELDS: &[&str] = &[
    "id",
    "name",
    "parameters",
    "sha256",
    "size_bytes",
    "version",
];

// Every editor path has an explicit v3 disposition. Nothing may be silently
// ignored by release compilation. Install-time and release-owned settings are
// bound into the release input even when they are not rendered by the desktop
// module itself.
pub const EDITOR_PATH_DISPOSITIONS: &[(&str, &str)] = &[
    // The editor's application channel is policy metadata. Executable package
    // selection is still frozen by exact package_ref values plus the release's
    // independently pinned nixpkgs commit.
    ("settings.apps.channel", "release_control"),
    ("settings.identity.loginmethod", "compiled"),
    ("settings.identity.localprofile", "compiled"),
    ("settings.identity.directoryprovider", "compiled"),
    ("settings.identity.fallback", "compiled"),
    ("settings.identity.sshkeys", "compiled"),
    ("settings.network.manager", "compiled"),
    ("settings.network.proxy", "compiled"),
    ("settings.network.dns", "compiled"),
    ("settings.network.priority", "compiled"),
    ("settings.network.vpn", "compiled"),
    ("settings.network.eap", "compiled"),
    ("settings.desktop.profile", "compiled"),
    ("settings.desktop.de", "compiled"),
    ("settings.desktop.greeter", "compiled"),
    ("settings.desktop.layout", "compiled"),
    ("settings.desktop.overview", "compiled"),
    ("settings.desktop.panel", "compiled"),
    ("settings.desktop.shell", "compiled"),
    ("settings.desktop.launcher", "compiled"),
    ("settings.desktop.terminal", "compiled"),
    ("settings.desktop.keybindings", "compiled"),
    ("settings.desktop.screenshots", "compiled"),
    ("settings.desktop.login", "compiled"),
    ("settings.desktop.loginuser", "compiled"),
    ("settings.desktop.portal", "compiled"),
    ("settings.desktop.audio", "compiled"),
    ("settings.desktop.bluetooth", "compiled"),
    ("settings.desktop.browser", "compiled"),
    ("settings.desktop.kioskapp", "compiled"),
    ("settings.desktop.kioskurl", "compiled"),
    ("settings.desktop.wallpaper", "compiled"),
    ("settings.desktop.language", "compiled"),
    ("settings.desktop.keyboard", "compiled"),
    ("settings.desktop.timezone", "compiled"),
    ("settings.desktop.dock", "compiled"),
    ("settings.desktop.a11y", "compiled"),
    ("settings.desktop.theme", "compiled"),
    ("settings.desktop.icons", "compiled"),
    ("settings.desktop.cursor", "compiled"),
    ("settings.desktop.titlebar", "compiled"),
    ("settings.desktop.dconf", "compiled"),
    ("settings.desktop.kconfig", "compiled"),
    ("settings.desktop.hyprland", "compiled"),
    ("settings.desktop.hyprbinds", "compiled"),
    ("settings.printing.defprinter", "compiled"),
    ("settings.printing.printervis", "compiled"),
    ("settings.printing.driver", "compiled"),
    ("settings.security.encryption", "baseline_constraint"),
    ("settings.security.firewall", "compiled"),
    ("settings.security.ssh", "compiled"),
    ("settings.security.screenlock", "compiled"),
    ("settings.security.passrules", "compiled"),
    ("settings.security.sudo", "compiled"),
    ("settings.security.usb", "compiled"),
    ("settings.security.cammic", "compiled"),
    ("settings.security.compliance", "compiled"),
    ("settings.updates.oschannel", "release_control"),
    ("settings.updates.cadence", "release_control"),
    ("settings.updates.window", "release_control"),
    ("settings.updates.reboot", "release_control"),
    ("settings.updates.rollback", "release_control"),
    ("settings.updates.canary", "release_control"),
    ("settings.restrictions.terminal", "compiled"),
    ("settings.restrictions.browserrest", "compiled"),
    ("settings.restrictions.urllist", "compiled"),
    ("settings.restrictions.ext", "compiled"),
    ("settings.restrictions.kiosk", "compiled"),
    ("settings.restrictions.exam", "compiled"),
    ("settings.restrictions.extstorage", "compiled"),
    ("settings.restrictions.screenshot", "compiled"),
    ("settings.storage.home", "install_time"),
    ("settings.storage.smbnfs", "compiled"),
    ("settings.storage.downloads", "compiled"),
    ("settings.storage.backup", "compiled"),
    ("settings.storage.sessclean", "compiled"),
    ("settings.monitoring.inventory", "compiled"),
    ("settings.monitoring.heartbeat", "compiled"),
    ("settings.monitoring.logs", "compiled"),
    ("settings.monitoring.telemetry", "compiled"),
    ("settings.monitoring.alerts", "compiled"),
    ("settings.monitoring.minagent", "compiled"),
    ("settings.advanced.rawnix", "governed_extension"),
    ("settings.advanced.customcmd", "governed_extension"),
    ("settings.advanced.kernel", "compiled"),
    ("settings.advanced.experimental", "compiled"),
    ("settings.advanced.capture_name", "capture_metadata"),
    ("settings.advanced.capture_manifest", "capture_metadata"),
    ("settings.advanced.capture_assets", "asset_manifest"),
];

pub fn editor_path_disposition(path: &str) -> Option<&'static str> {
    EDITOR_PATH_DISPOSITIONS
        .iter()
        .find_map(|(candidate, disposition)| (*candidate == path).then_some(*disposition))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerivedProjection {
    pub source_config: Value,
    pub source_config_sha256: String,
    pub typed_config: Value,
    pub typed_config_sha256: String,
    pub asset_manifest: Value,
    pub asset_manifest_sha256: String,
    pub extension_manifest: Value,
    pub extension_manifest_sha256: String,
    pub coverage: Value,
}

impl DerivedProjection {
    pub fn into_wire(self) -> Value {
        json!({
            "schema": PROJECTION_SCHEMA,
            "compiler_revision": PROJECTION_REVISION,
            "source_config": self.source_config,
            "source_config_sha256": self.source_config_sha256,
            "typed_config": self.typed_config,
            "typed_config_sha256": self.typed_config_sha256,
            "asset_manifest": self.asset_manifest,
            "asset_manifest_sha256": self.asset_manifest_sha256,
            "extension_manifest": self.extension_manifest,
            "extension_manifest_sha256": self.extension_manifest_sha256,
            "coverage": self.coverage,
        })
    }
}

pub fn derive_projection(source: &Value) -> Result<DerivedProjection, String> {
    let mut visited = 0usize;
    validate_bounded_value(source, "source_config", 0, &mut visited)?;
    reject_secret_material(source, "source_config")?;
    let root = object(source, "source_config")?;
    allowed_keys(
        root,
        &[
            "extensions",
            "lists",
            "local_account_profile_selection_mode",
            "settings",
        ],
        "source_config",
    )?;
    if let Some(mode) = root.get("local_account_profile_selection_mode") {
        exact_string(
            Some(mode),
            "explicit",
            "local_account_profile_selection_mode",
        )?;
    }

    let settings = object(
        root.get("settings")
            .ok_or("source_config.settings is missing")?,
        "settings",
    )?;
    let mut coverage = Vec::new();
    if root.contains_key("local_account_profile_selection_mode") {
        coverage.push(coverage_entry(
            "local_account_profile_selection_mode",
            "identity_control",
        ));
    }
    validate_settings(settings, &mut coverage)?;
    if setting_text(settings, "security", "encryption")
        .is_some_and(|encryption| !encryption.to_ascii_lowercase().contains("luks2"))
    {
        return Err(
            "settings.security.encryption conflicts with the managed LUKS2 baseline".into(),
        );
    }
    if let Some(os_channel) = setting_text(settings, "updates", "oschannel") {
        let os_channel = os_channel.trim().to_ascii_lowercase();
        if os_channel != "nixpkgs stable" && !os_channel.contains("26.05") {
            return Err(
                "settings.updates.oschannel conflicts with the managed 26.05 stable OS line".into(),
            );
        }
    }

    let lists = object(
        root.get("lists").ok_or("source_config.lists is missing")?,
        "lists",
    )?;
    let mut applications = validate_lists(lists, &mut coverage)?;
    if !applications.iter().any(|application| {
        application.get("package_ref").and_then(Value::as_str) == Some("cybex-agent")
    }) {
        applications.push(json!({
            "package_ref": "cybex-agent",
            "package_source": "managed",
        }));
        applications.sort_by(|left, right| {
            left["package_ref"]
                .as_str()
                .cmp(&right["package_ref"].as_str())
        });
    }

    let (source_config, assets) = normalized_source_and_assets(source)?;
    let extensions = validate_extensions(root.get("extensions"), &mut coverage)?;
    coverage.sort_by(|left, right| left["path"].as_str().cmp(&right["path"].as_str()));

    let asset_manifest = json!({
        "schema": ASSET_MANIFEST_SCHEMA,
        "assets": assets,
    });
    let extension_manifest = json!({
        "schema": EXTENSION_MANIFEST_SCHEMA,
        "modules": extensions,
    });
    let semantic_intent = semantic_intent(&source_config);
    let typed_config = json!({
        "schema": TYPED_CONFIG_SCHEMA,
        "intent": semantic_intent,
        "desktop": desktop_summary(settings),
        "services": {
            "docker": applications.iter().any(|application| {
                application.get("package_ref").and_then(Value::as_str) == Some("docker")
                    || application.get("label").and_then(Value::as_str)
                        .is_some_and(|label| label.eq_ignore_ascii_case("Docker"))
            }),
        },
        "security": {
            "root_encryption": "luks2_required",
        },
        "release_control": {
            "source_os_line": "26.05",
            "auto_upgrade": false,
        },
        "applications": applications,
        "asset_manifest_sha256": canonical_json_sha256(&asset_manifest)?,
        "extension_manifest_sha256": canonical_json_sha256(&extension_manifest)?,
        "managed_agent_declared": true,
    });
    let source_bytes = canonical_json_bytes(&source_config)?;
    if source_bytes.len() > MAX_SOURCE_BYTES {
        return Err("normalized Blueprint source exceeds the compiler byte bound".into());
    }
    let source_config_sha256 = hex::encode(Sha256::digest(&source_bytes));
    let typed_config_sha256 = canonical_json_sha256(&typed_config)?;
    let asset_manifest_sha256 = canonical_json_sha256(&asset_manifest)?;
    let extension_manifest_sha256 = canonical_json_sha256(&extension_manifest)?;
    Ok(DerivedProjection {
        source_config,
        source_config_sha256,
        typed_config,
        typed_config_sha256,
        asset_manifest,
        asset_manifest_sha256,
        extension_manifest,
        extension_manifest_sha256,
        coverage: Value::Array(coverage),
    })
}

fn setting_text<'a>(
    settings: &'a Map<String, Value>,
    domain: &str,
    setting: &str,
) -> Option<&'a str> {
    settings
        .get(domain)
        .and_then(Value::as_object)
        .and_then(|domain| domain.get(setting))
        .and_then(Value::as_object)
        .and_then(|setting| setting.get("value"))
        .and_then(Value::as_str)
}

fn semantic_intent(source: &Value) -> Value {
    let mut semantic = source.clone();
    if let Some(settings) = semantic.get_mut("settings").and_then(Value::as_object_mut) {
        for domain in settings.values_mut().filter_map(Value::as_object_mut) {
            for setting in domain.values_mut().filter_map(Value::as_object_mut) {
                setting.remove("label");
                setting.remove("source");
                setting.remove("locked");
                setting.remove("required");
                setting.remove("captured");
                setting.remove("hint");
            }
        }
        if let Some(advanced) = settings.get_mut("advanced").and_then(Value::as_object_mut) {
            advanced.remove("capture_name");
            advanced.remove("capture_manifest");
            if advanced.is_empty() {
                settings.remove("advanced");
            }
        }
    }
    if let Some(lists) = semantic.get_mut("lists").and_then(Value::as_object_mut) {
        lists.remove("capture");
        for sections in lists.values_mut().filter_map(Value::as_object_mut) {
            for section in sections.values_mut().filter_map(Value::as_object_mut) {
                section.remove("title");
                section.remove("icon");
                if let Some(items) = section.get_mut("items").and_then(Value::as_array_mut) {
                    for item in items.iter_mut().filter_map(Value::as_object_mut) {
                        for field in [
                            "description",
                            "homepage",
                            "icon",
                            "icon_available",
                            "id",
                            "license",
                            "locked",
                            "meta",
                            "platforms",
                            "required",
                            "search_branch",
                            "source",
                            "version",
                        ] {
                            item.remove(field);
                        }
                    }
                }
            }
        }
    }
    semantic
}

pub fn validate_projection(value: &Value) -> Result<DerivedProjection, String> {
    let projection = object(value, "projection")?;
    exact_keys(
        projection,
        &[
            "asset_manifest",
            "asset_manifest_sha256",
            "compiler_revision",
            "coverage",
            "extension_manifest",
            "extension_manifest_sha256",
            "schema",
            "source_config",
            "source_config_sha256",
            "typed_config",
            "typed_config_sha256",
        ],
        "projection",
    )?;
    exact_string(
        projection.get("schema"),
        PROJECTION_SCHEMA,
        "projection.schema",
    )?;
    exact_string(
        projection.get("compiler_revision"),
        PROJECTION_REVISION,
        "projection.compiler_revision",
    )?;
    let derived = derive_projection(
        projection
            .get("source_config")
            .ok_or("projection.source_config is missing")?,
    )?;
    for (field, expected) in [
        ("source_config_sha256", &derived.source_config_sha256),
        ("typed_config_sha256", &derived.typed_config_sha256),
        ("asset_manifest_sha256", &derived.asset_manifest_sha256),
        (
            "extension_manifest_sha256",
            &derived.extension_manifest_sha256,
        ),
    ] {
        exact_string(
            projection.get(field),
            expected,
            &format!("projection.{field}"),
        )?;
    }
    for (field, expected) in [
        ("typed_config", &derived.typed_config),
        ("asset_manifest", &derived.asset_manifest),
        ("extension_manifest", &derived.extension_manifest),
        ("coverage", &derived.coverage),
    ] {
        if projection.get(field) != Some(expected) {
            return Err(format!(
                "projection {field} does not match independent compiler derivation"
            ));
        }
    }
    Ok(derived)
}

fn validate_settings(
    settings: &Map<String, Value>,
    coverage: &mut Vec<Value>,
) -> Result<(), String> {
    for (domain, domain_value) in settings {
        if domain.is_empty() || domain.len() > 64 || !safe_identifier(domain) {
            return Err("settings contains an invalid domain".into());
        }
        let domain_settings = object(domain_value, &format!("settings.{domain}"))?;
        for (setting, value) in domain_settings {
            if setting.is_empty() || setting.len() > 64 || !safe_identifier(setting) {
                return Err(format!("settings.{domain} contains an invalid setting ID"));
            }
            let path = format!("settings.{domain}.{setting}");
            let disposition = editor_path_disposition(&path)
                .ok_or_else(|| format!("{path} has no compiler-v3 disposition"))?;
            let setting_value = object(value, &path)?;
            allowed_keys(setting_value, SETTING_FIELDS, &path)?;
            if !setting_value.contains_key("value") {
                return Err(format!("{path}.value is missing"));
            }
            optional_text(setting_value.get("label"), 256, &format!("{path}.label"))?;
            optional_text(setting_value.get("source"), 128, &format!("{path}.source"))?;
            for field in ["locked", "required", "captured"] {
                if setting_value
                    .get(field)
                    .is_some_and(|value| !value.is_boolean())
                {
                    return Err(format!("{path}.{field} must be a boolean"));
                }
            }
            if disposition == "governed_extension"
                && setting_value
                    .get("value")
                    .and_then(Value::as_str)
                    .is_some_and(|value| !extension_placeholder_is_empty(value))
            {
                return Err(format!(
                    "{path} contains executable material; publish it as an approved extensions.modules artifact"
                ));
            }
            coverage.push(coverage_entry(&path, disposition));
        }
    }
    Ok(())
}

fn validate_lists(
    lists: &Map<String, Value>,
    coverage: &mut Vec<Value>,
) -> Result<Vec<Value>, String> {
    let allowed_sections: BTreeMap<&str, &[&str]> = BTreeMap::from([
        (
            "apps",
            &["forbidden", "installed", "required", "selfservice"][..],
        ),
        ("capture", &["selected"][..]),
        ("network", &["certs", "wifi"][..]),
        ("printing", &["printers", "servers"][..]),
        ("storage", &["shares"][..]),
    ]);
    let mut application_count = 0usize;
    let mut applications = BTreeMap::<String, Value>::new();
    let mut total_items = 0usize;
    for (domain, domain_value) in lists {
        let sections = allowed_sections
            .get(domain.as_str())
            .ok_or_else(|| format!("lists.{domain} is outside compiler-v3 coverage"))?;
        let domain_object = object(domain_value, &format!("lists.{domain}"))?;
        for (section, section_value) in domain_object {
            if !sections.contains(&section.as_str()) {
                return Err(format!(
                    "lists.{domain}.{section} is outside compiler-v3 coverage"
                ));
            }
            let path = format!("lists.{domain}.{section}");
            let section_object = object(section_value, &path)?;
            allowed_keys(section_object, LIST_SECTION_FIELDS, &path)?;
            optional_text(section_object.get("title"), 256, &format!("{path}.title"))?;
            optional_text(section_object.get("icon"), 128, &format!("{path}.icon"))?;
            optional_text(section_object.get("policy"), 64, &format!("{path}.policy"))?;
            if section_object
                .get("capture_authoritative")
                .is_some_and(|value| !value.is_boolean())
            {
                return Err(format!("{path}.capture_authoritative must be a boolean"));
            }
            let items = section_object
                .get("items")
                .and_then(Value::as_array)
                .ok_or_else(|| format!("{path}.items must be an array"))?;
            total_items = total_items
                .checked_add(items.len())
                .ok_or_else(|| "Blueprint list item count overflow".to_string())?;
            if total_items > MAX_LIST_ITEMS {
                return Err("Blueprint list items exceed the compiler bound".into());
            }
            let section_disposition = if domain == "capture" {
                "capture_metadata"
            } else if domain == "apps" && section == "forbidden" {
                "policy_constraint"
            } else {
                "compiled"
            };
            coverage.push(coverage_entry(&path, section_disposition));
            for (index, item) in items.iter().enumerate() {
                let item_path = format!("{path}.items[{index}]");
                let item = object(item, &item_path)?;
                allowed_keys(item, LIST_ITEM_FIELDS, &item_path)?;
                optional_text(item.get("id"), 256, &format!("{item_path}.id"))?;
                optional_text(item.get("label"), 256, &format!("{item_path}.label"))?;
                optional_text(item.get("meta"), 1024, &format!("{item_path}.meta"))?;
                optional_text(item.get("source"), 128, &format!("{item_path}.source"))?;
                for field in ["required", "locked", "removed", "unfree", "icon_available"] {
                    if item.get(field).is_some_and(|value| !value.is_boolean()) {
                        return Err(format!("{item_path}.{field} must be a boolean"));
                    }
                }
                if domain == "apps" && section != "forbidden" {
                    if item
                        .get("removed")
                        .and_then(Value::as_bool)
                        .unwrap_or(false)
                    {
                        coverage.push(coverage_entry(&item_path, "removed"));
                        continue;
                    }
                    application_count += 1;
                    if application_count > MAX_APPLICATIONS {
                        return Err("Blueprint applications exceed the compiler bound".into());
                    }
                    let package_ref = required_text(
                        item.get("package_ref"),
                        1,
                        256,
                        &format!("{item_path}.package_ref"),
                    )?;
                    validate_package_ref(package_ref)?;
                    if item.get("package_source").is_some() {
                        exact_string(
                            item.get("package_source"),
                            "nixpkgs",
                            &format!("{item_path}.package_source"),
                        )?;
                    }
                    let label = item
                        .get("label")
                        .and_then(Value::as_str)
                        .unwrap_or(package_ref);
                    let key = package_ref.to_ascii_lowercase();
                    if applications
                        .insert(key, json!({"label": label, "package_ref": package_ref}))
                        .is_some()
                    {
                        return Err(format!("{item_path}.package_ref is duplicated"));
                    }
                }
                coverage.push(coverage_entry(&item_path, section_disposition));
            }
        }
    }
    Ok(applications.into_values().collect())
}

fn normalized_source_and_assets(source: &Value) -> Result<(Value, Vec<Value>), String> {
    let mut normalized = source.clone();
    let Some(setting) = normalized
        .pointer_mut("/settings/advanced/capture_assets")
        .and_then(Value::as_object_mut)
    else {
        return Ok((normalized, Vec::new()));
    };
    let source_user = setting
        .get("source_user")
        .and_then(Value::as_str)
        .map(validate_source_user)
        .transpose()?;
    let items = setting
        .get_mut("value")
        .and_then(Value::as_array_mut)
        .ok_or("settings.advanced.capture_assets.value must be an array")?;
    if items.len() > MAX_ASSETS {
        return Err("captured asset count exceeds the compiler bound".into());
    }
    let mut assets = Vec::with_capacity(items.len());
    let mut seen_paths = BTreeSet::new();
    let mut total_bytes = 0u64;
    for (index, item) in items.iter_mut().enumerate() {
        let path = format!("settings.advanced.capture_assets.value[{index}]");
        let object = object(item, &path)?;
        allowed_keys(object, CAPTURE_ASSET_FIELDS, &path)?;
        let logical_path = required_text(
            object.get("logical_path"),
            1,
            1024,
            &format!("{path}.logical_path"),
        )?;
        validate_logical_path(logical_path)?;
        if !seen_paths.insert(logical_path.to_string()) {
            return Err("captured asset logical paths must be unique".into());
        }
        let category = required_text(object.get("category"), 1, 64, &format!("{path}.category"))?;
        let mime_type = required_text(
            object.get("mime_type"),
            1,
            128,
            &format!("{path}.mime_type"),
        )?;
        let sha256 = required_sha256(object.get("sha256"), &format!("{path}.sha256"))?;
        let size_bytes = object
            .get("size_bytes")
            .and_then(Value::as_u64)
            .ok_or_else(|| format!("{path}.size_bytes must be an unsigned integer"))?;
        if size_bytes > MAX_ASSET_BYTES {
            return Err(format!("{path}.size_bytes exceeds the per-asset bound"));
        }
        total_bytes = total_bytes
            .checked_add(size_bytes)
            .ok_or_else(|| "captured asset size overflow".to_string())?;
        if total_bytes > MAX_ASSET_TOTAL_BYTES {
            return Err("captured assets exceed the total byte bound".into());
        }
        if let Some(content) = object.get("content_base64").and_then(Value::as_str) {
            let bytes = STANDARD
                .decode(content.as_bytes())
                .map_err(|_| format!("{path}.content_base64 is invalid"))?;
            if bytes.len() as u64 != size_bytes || hex::encode(Sha256::digest(&bytes)) != sha256 {
                return Err(format!(
                    "{path}.content_base64 does not match its declared digest and size"
                ));
            }
        }
        let application_mode = object
            .get("application_mode")
            .and_then(Value::as_str)
            .unwrap_or_else(|| {
                if logical_path.starts_with("home/") {
                    "seed_once"
                } else {
                    "enforced"
                }
            });
        if !matches!(
            application_mode,
            "enforced" | "managed_default" | "seed_once"
        ) {
            return Err(format!("{path}.application_mode is unsupported"));
        }
        let target_scope = object
            .get("target_scope")
            .and_then(Value::as_str)
            .unwrap_or_else(|| {
                if logical_path.starts_with("home/") {
                    "captured_user"
                } else {
                    "system"
                }
            });
        if !matches!(target_scope, "captured_user" | "system") {
            return Err(format!("{path}.target_scope is unsupported"));
        }
        let target_path = asset_target_path(logical_path, source_user.as_deref(), target_scope)?;
        assets.push(json!({
            "logical_path": logical_path,
            "category": category,
            "media_type": mime_type,
            "sha256": sha256,
            "size_bytes": size_bytes,
            "application_mode": application_mode,
            "target_scope": target_scope,
            "target_path": target_path,
        }));
        item.as_object_mut()
            .expect("validated asset object")
            .remove("content_base64");
    }
    assets.sort_by(|left, right| {
        left["logical_path"]
            .as_str()
            .cmp(&right["logical_path"].as_str())
    });
    Ok((normalized, assets))
}

fn validate_extensions(
    extensions: Option<&Value>,
    coverage: &mut Vec<Value>,
) -> Result<Vec<Value>, String> {
    let Some(extensions) = extensions else {
        return Ok(Vec::new());
    };
    let extensions = object(extensions, "extensions")?;
    exact_keys(extensions, &["modules"], "extensions")?;
    let modules = extensions["modules"]
        .as_array()
        .ok_or("extensions.modules must be an array")?;
    if modules.len() > MAX_EXTENSIONS {
        return Err("extensions.modules exceeds the compiler bound".into());
    }
    let mut result = Vec::with_capacity(modules.len());
    let mut seen = BTreeSet::new();
    let mut seen_names = BTreeSet::new();
    let mut total_bytes = 0u64;
    for (index, module) in modules.iter().enumerate() {
        let path = format!("extensions.modules[{index}]");
        let module = object(module, &path)?;
        exact_keys(module, EXTENSION_FIELDS, &path)?;
        let id = required_text(module.get("id"), 1, 128, &format!("{path}.id"))?;
        if !safe_extension_id(id) || !seen.insert(id.to_string()) {
            return Err(format!("{path}.id is invalid or duplicated"));
        }
        let name = required_text(module.get("name"), 1, 160, &format!("{path}.name"))?;
        if !seen_names.insert(name.to_string()) {
            return Err(format!("{path}.name is duplicated"));
        }
        let version = required_text(module.get("version"), 1, 80, &format!("{path}.version"))?;
        let sha256 = required_sha256(module.get("sha256"), &format!("{path}.sha256"))?;
        let size_bytes = module
            .get("size_bytes")
            .and_then(Value::as_u64)
            .filter(|size| *size > 0 && *size <= MAX_ASSET_BYTES)
            .ok_or_else(|| format!("{path}.size_bytes is outside its bound"))?;
        total_bytes = total_bytes
            .checked_add(size_bytes)
            .ok_or("extensions.modules total size overflows its bound")?;
        if total_bytes > MAX_EXTENSION_TOTAL_BYTES {
            return Err("extensions.modules exceeds the total byte bound".into());
        }
        let parameters = object(
            module
                .get("parameters")
                .ok_or_else(|| format!("{path}.parameters is missing"))?,
            &format!("{path}.parameters"),
        )?;
        result.push(json!({
            "id": id,
            "name": name,
            "version": version,
            "sha256": sha256,
            "size_bytes": size_bytes,
            "parameters": parameters,
        }));
        coverage.push(coverage_entry(&path, "governed_extension"));
    }
    result.sort_by(|left, right| left["id"].as_str().cmp(&right["id"].as_str()));
    Ok(result)
}

fn desktop_summary(settings: &Map<String, Value>) -> Value {
    let value = |setting: &str| {
        settings
            .get("desktop")
            .and_then(Value::as_object)
            .and_then(|desktop| desktop.get(setting))
            .and_then(|setting| setting.get("value"))
            .cloned()
            .unwrap_or(Value::Null)
    };
    json!({
        "profile": value("profile"),
        "environment": value("de"),
        "greeter": value("greeter"),
        "wallpaper": value("wallpaper"),
        "dock": value("dock"),
        "shell": value("shell"),
        "launcher": value("launcher"),
        "terminal": value("terminal"),
    })
}

fn asset_target_path(
    logical_path: &str,
    source_user: Option<&str>,
    target_scope: &str,
) -> Result<String, String> {
    if target_scope == "captured_user" {
        let user = source_user
            .ok_or("captured user assets require settings.advanced.capture_assets.source_user")?;
        let relative = logical_path
            .strip_prefix("home/")
            .ok_or("captured user asset must use the home/ logical prefix")?;
        return Ok(format!("/home/{user}/{relative}"));
    }
    Ok(format!("/etc/cybex/blueprint-assets/{logical_path}"))
}

fn validate_source_user(value: &str) -> Result<String, String> {
    if value.is_empty()
        || value.len() > 32
        || !value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (index > 0 && matches!(byte, b'_' | b'-'))
        })
        || !value.as_bytes()[0].is_ascii_lowercase()
    {
        return Err("captured source_user is invalid".into());
    }
    Ok(value.to_string())
}

fn validate_logical_path(value: &str) -> Result<(), String> {
    if value.starts_with('/')
        || value.ends_with('/')
        || value.contains("//")
        || value.contains('\\')
        || value
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
        || value
            .chars()
            .any(|ch| ch.is_control() || matches!(ch, ':' | '*' | '?' | '"' | '<' | '>' | '|'))
    {
        return Err("captured asset logical_path is unsafe".into());
    }
    Ok(())
}

fn extension_placeholder_is_empty(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "" | "none" | "off" | "disabled"
    )
}

fn reject_secret_material(value: &Value, path: &str) -> Result<(), String> {
    const FORBIDDEN_KEYS: &[&str] = &[
        "access_token",
        "api_key",
        "credential",
        "credentials",
        "password",
        "private_key",
        "refresh_token",
        "secret",
        "token",
    ];
    match value {
        Value::Object(values) => {
            for (key, child) in values {
                let normalized = key.trim().to_ascii_lowercase().replace('-', "_");
                if FORBIDDEN_KEYS.contains(&normalized.as_str()) {
                    return Err(format!("{path} contains secret-bearing material"));
                }
                reject_secret_material(child, path)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                reject_secret_material(child, path)?;
            }
        }
        Value::String(text) => {
            let lower = text.to_ascii_lowercase();
            if lower.contains("secret://")
                || lower.contains("-----begin private key-----")
                || lower.contains("-----begin openssh private key-----")
                || lower.contains("authorization: bearer")
            {
                return Err(format!("{path} contains secret-bearing material"));
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_bounded_value(
    value: &Value,
    path: &str,
    depth: usize,
    visited: &mut usize,
) -> Result<(), String> {
    if depth > MAX_DEPTH {
        return Err(format!("{path} exceeds the compiler depth bound"));
    }
    *visited += 1;
    if *visited > MAX_VALUES {
        return Err(format!("{path} exceeds the compiler complexity bound"));
    }
    match value {
        Value::Null | Value::Bool(_) => Ok(()),
        Value::Number(number) => {
            if number.as_i64().is_none() && number.as_u64().is_none() {
                Err(format!("{path} contains a non-integer number"))
            } else {
                Ok(())
            }
        }
        Value::String(text) => {
            if text.len() > MAX_SOURCE_BYTES
                || text
                    .chars()
                    .any(|ch| ch == '\0' || (ch.is_control() && !matches!(ch, '\n' | '\r' | '\t')))
            {
                Err(format!("{path} contains an invalid or oversized string"))
            } else {
                Ok(())
            }
        }
        Value::Array(values) => {
            for child in values {
                validate_bounded_value(child, path, depth + 1, visited)?;
            }
            Ok(())
        }
        Value::Object(values) => {
            for (key, child) in values {
                if key.is_empty() || key.len() > 256 || key.chars().any(char::is_control) {
                    return Err(format!("{path} contains an invalid object key"));
                }
                validate_bounded_value(child, path, depth + 1, visited)?;
            }
            Ok(())
        }
    }
}

pub fn canonical_json_sha256(value: &Value) -> Result<String, String> {
    Ok(hex::encode(Sha256::digest(canonical_json_bytes(value)?)))
}

fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    write_canonical(value, &mut bytes)?;
    Ok(bytes)
}

fn write_canonical(value: &Value, output: &mut Vec<u8>) -> Result<(), String> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(true) => output.extend_from_slice(b"true"),
        Value::Bool(false) => output.extend_from_slice(b"false"),
        Value::Number(number) => {
            if number.as_i64().is_none() && number.as_u64().is_none() {
                return Err("canonical compiler input contains a non-integer number".into());
            }
            output.extend_from_slice(number.to_string().as_bytes());
        }
        Value::String(text) => output.extend_from_slice(
            serde_json::to_string(text)
                .map_err(|error| error.to_string())?
                .as_bytes(),
        ),
        Value::Array(values) => {
            output.push(b'[');
            for (index, child) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical(child, output)?;
            }
            output.push(b']');
        }
        Value::Object(values) => {
            output.push(b'{');
            let sorted = values.iter().collect::<BTreeMap<_, _>>();
            for (index, (key, child)) in sorted.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical(&Value::String(key.clone()), output)?;
                output.push(b':');
                write_canonical(child, output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

fn coverage_entry(path: &str, disposition: &str) -> Value {
    json!({"path": path, "disposition": disposition})
}

fn validate_package_ref(value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 256 || value.starts_with('.') || value.ends_with('.') {
        return Err("application package_ref is invalid".into());
    }
    for segment in value.split('.') {
        let mut chars = segment.chars();
        let Some(first) = chars.next() else {
            return Err("application package_ref has an empty segment".into());
        };
        if !(first.is_ascii_alphanumeric() || first == '_')
            || !chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '+'))
        {
            return Err("application package_ref is not a safe nixpkgs attribute path".into());
        }
    }
    Ok(())
}

fn safe_identifier(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn safe_extension_id(value: &str) -> bool {
    value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'/')
    })
}

fn object<'a>(value: &'a Value, path: &str) -> Result<&'a Map<String, Value>, String> {
    value
        .as_object()
        .ok_or_else(|| format!("{path} must be an object"))
}

fn exact_keys(object: &Map<String, Value>, expected: &[&str], path: &str) -> Result<(), String> {
    allowed_keys(object, expected, path)?;
    if let Some(missing) = expected.iter().find(|key| !object.contains_key(**key)) {
        return Err(format!("{path}.{missing} is missing"));
    }
    Ok(())
}

fn allowed_keys(object: &Map<String, Value>, allowed: &[&str], path: &str) -> Result<(), String> {
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(format!(
            "{path} contains a key outside compiler-v3 coverage"
        ));
    }
    Ok(())
}

fn exact_string(value: Option<&Value>, expected: &str, path: &str) -> Result<(), String> {
    if value.and_then(Value::as_str) != Some(expected) {
        return Err(format!("{path} must be {expected:?}"));
    }
    Ok(())
}

fn optional_text(value: Option<&Value>, max: usize, path: &str) -> Result<(), String> {
    if let Some(value) = value {
        required_text(Some(value), 0, max, path)?;
    }
    Ok(())
}

fn required_text<'a>(
    value: Option<&'a Value>,
    min: usize,
    max: usize,
    path: &str,
) -> Result<&'a str, String> {
    let text = value
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{path} must be a string"))?;
    if text.len() < min
        || text.len() > max
        || text
            .chars()
            .any(|ch| ch == '\0' || (ch.is_control() && !matches!(ch, '\n' | '\r' | '\t')))
    {
        return Err(format!("{path} is outside its text bounds"));
    }
    Ok(text)
}

fn required_sha256(value: Option<&Value>, path: &str) -> Result<String, String> {
    let value = required_text(value, 64, 64, path)?;
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(format!("{path} must be lowercase SHA-256"));
    }
    Ok(value.to_string())
}
