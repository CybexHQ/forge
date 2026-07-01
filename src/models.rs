use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::AppError;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Device {
    pub id: i64,
    pub mac: String,
    pub hostname: Option<String>,
    pub serial_number: Option<String>,
    pub last_seen_at: Option<String>,
    pub last_selected_profile_id: Option<i64>,
    pub notes: String,
    pub tags: Vec<String>,
    pub default_profile_id: Option<i64>,
    pub one_time_profile_id: Option<i64>,
    pub one_time_consumed_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BootProfile {
    pub id: i64,
    pub managed_profile_id: Option<String>,
    pub name: String,
    pub description: String,
    pub profile_type: BootProfileType,
    pub installer_iso_source: String,
    pub enabled: bool,
    pub is_default: bool,
    pub one_time: bool,
    pub kernel_path: Option<String>,
    pub initrd_path: Option<String>,
    pub iso_path: Option<String>,
    pub cmdline: Option<String>,
    pub raw_script: Option<String>,
    pub desired_iso_artifact_id: String,
    pub desired_iso_filename: String,
    pub desired_iso_size_bytes: i64,
    pub desired_iso_sha256: String,
    pub desired_iso_built_at: Option<String>,
    pub desired_iso_url: String,
    pub desired_iso_download_url: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootProfileType {
    LocalDisk,
    IsoLive,
    LinuxInstaller,
    CustomIpxe,
}

impl BootProfileType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LocalDisk => "local_disk",
            Self::IsoLive => "iso_live",
            Self::LinuxInstaller => "linux_installer",
            Self::CustomIpxe => "custom_ipxe",
        }
    }
}

impl fmt::Display for BootProfileType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for BootProfileType {
    type Err = AppError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "local_disk" => Ok(Self::LocalDisk),
            "iso_live" => Ok(Self::IsoLive),
            "linux_installer" => Ok(Self::LinuxInstaller),
            "custom_ipxe" => Ok(Self::CustomIpxe),
            other => Err(AppError::Validation(format!(
                "unsupported boot profile type '{other}'"
            ))),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IsoAsset {
    pub id: i64,
    pub filename: String,
    pub relative_path: String,
    pub size_bytes: i64,
    pub checksum_sha256: String,
    pub last_scanned_at: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BuildJob {
    pub id: i64,
    pub managed_job_id: Option<String>,
    pub requested_artifact_type: String,
    pub build_spec: Value,
    pub target: String,
    pub system: String,
    pub input_revision: String,
    pub input_config_hash: String,
    pub status: String,
    pub logs: String,
    pub error: String,
    pub output_path: String,
    pub output_sha256: String,
    pub output_size_bytes: i64,
    pub exit_code: Option<i64>,
    pub cache_metadata: Value,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub cancel_requested_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CacheArtifact {
    pub id: i64,
    pub managed_artifact_id: Option<String>,
    pub artifact_type: String,
    pub hash: String,
    pub size_bytes: i64,
    pub path: String,
    pub store_path: String,
    pub narinfo_path: String,
    pub nar_url: String,
    pub file_hash: String,
    pub nar_hash: String,
    pub nar_size_bytes: i64,
    pub closure_size_bytes: i64,
    pub compression: String,
    pub references: Value,
    pub serving_url: String,
    pub source_build_job_id: Option<String>,
    pub cache_metadata: Value,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateBuildJobRequest {
    pub requested_artifact_type: String,
    #[serde(default)]
    pub build_spec: Option<Value>,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub system: Option<String>,
    pub input_revision: String,
    pub input_config_hash: String,
    pub cache_metadata: Option<Value>,
}

#[derive(Debug, Deserialize)]
pub struct CreateCacheArtifactRequest {
    pub artifact_type: String,
    pub hash: String,
    pub size_bytes: i64,
    pub path: String,
    #[serde(default)]
    pub store_path: Option<String>,
    #[serde(default)]
    pub narinfo_path: Option<String>,
    #[serde(default)]
    pub nar_url: Option<String>,
    #[serde(default)]
    pub file_hash: Option<String>,
    #[serde(default)]
    pub nar_hash: Option<String>,
    #[serde(default)]
    pub nar_size_bytes: Option<i64>,
    #[serde(default)]
    pub closure_size_bytes: Option<i64>,
    #[serde(default)]
    pub compression: Option<String>,
    #[serde(default)]
    pub references: Option<Value>,
    pub serving_url: Option<String>,
    pub source_build_job_id: Option<String>,
    pub cache_metadata: Option<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BootEvent {
    pub id: i64,
    pub device_id: Option<i64>,
    pub mac: Option<String>,
    pub serial_number: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub selected_profile_id: Option<i64>,
    pub selected_profile_name: Option<String>,
    pub known_device: bool,
    pub created_at: String,
}

#[derive(Clone, Debug)]
pub struct NewBootEvent {
    pub device_id: Option<i64>,
    pub mac: Option<String>,
    pub serial_number: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub selected_profile_id: Option<i64>,
    pub selected_profile_name: Option<String>,
    pub known_device: bool,
}

#[derive(Debug, Deserialize)]
pub struct CreateDeviceRequest {
    pub mac: String,
    pub hostname: Option<String>,
    pub serial_number: Option<String>,
    pub notes: Option<String>,
    pub tags: Option<Vec<String>>,
    pub default_profile_id: Option<i64>,
    pub one_time_profile_id: Option<i64>,
}

#[derive(Debug, Default, Deserialize)]
pub struct UpdateDeviceRequest {
    pub hostname: Option<Option<String>>,
    pub serial_number: Option<Option<String>>,
    pub notes: Option<String>,
    pub tags: Option<Vec<String>>,
    pub default_profile_id: Option<Option<i64>>,
    pub one_time_profile_id: Option<Option<i64>>,
}

#[derive(Debug, Deserialize)]
pub struct CreateBootProfileRequest {
    pub name: String,
    pub description: Option<String>,
    pub profile_type: BootProfileType,
    pub enabled: Option<bool>,
    pub is_default: Option<bool>,
    pub one_time: Option<bool>,
    pub kernel_path: Option<String>,
    pub initrd_path: Option<String>,
    pub iso_path: Option<String>,
    pub cmdline: Option<String>,
    pub raw_script: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct UpdateBootProfileRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub profile_type: Option<BootProfileType>,
    pub enabled: Option<bool>,
    pub is_default: Option<bool>,
    pub one_time: Option<bool>,
    pub kernel_path: Option<Option<String>>,
    pub initrd_path: Option<Option<String>>,
    pub iso_path: Option<Option<String>>,
    pub cmdline: Option<Option<String>>,
    pub raw_script: Option<Option<String>>,
}

pub fn normalize_mac(input: &str) -> Result<String, AppError> {
    let compact: String = input
        .trim()
        .replace('-', ":")
        .split(':')
        .collect::<Vec<_>>()
        .join("")
        .to_ascii_lowercase();

    if compact.len() != 12 || !compact.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AppError::Validation(format!(
            "invalid MAC address '{input}'"
        )));
    }

    let mut out = Vec::with_capacity(6);
    for idx in 0..6 {
        out.push(&compact[idx * 2..idx * 2 + 2]);
    }
    Ok(out.join(":"))
}

pub fn clean_optional_string(value: Option<String>) -> Option<String> {
    value.and_then(|s| {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

pub fn clean_tags(tags: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = tags
        .into_iter()
        .map(|tag| tag.trim().to_ascii_lowercase())
        .filter(|tag| !tag.is_empty())
        .collect();
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::normalize_mac;

    #[test]
    fn normalizes_common_mac_formats() {
        assert_eq!(
            normalize_mac("AA-BB-CC-DD-EE-FF").unwrap(),
            "aa:bb:cc:dd:ee:ff"
        );
        assert_eq!(normalize_mac("aabbccddeeff").unwrap(), "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn rejects_invalid_mac() {
        assert!(normalize_mac("not-a-mac").is_err());
        assert!(normalize_mac("aa:bb:cc").is_err());
    }
}
