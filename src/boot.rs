use std::{cmp::Reverse, fmt::Write as _};

use crate::{
    assets::asset_url,
    error::AppResult,
    models::{BootProfile, BootProfileType, Device},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectionSource {
    OneTime,
    Assigned,
    Menu,
}

#[derive(Debug)]
pub struct ProfileSelection<'a> {
    pub profile: Option<&'a BootProfile>,
    pub source: SelectionSource,
}

const IPXE_MENU_BACKGROUND_PATH: &str = "assets/pxe-menu.png";
const IPXE_MENU_TITLE: &str = "CYBEX";
const IPXE_MENU_SUBTITLE: &str = "PXE BOOT - FORGE BOOT - X86_64 - UEFI";
const IPXE_MENU_TIMEOUT_COPY: &str =
    "Booting the highlighted entry automatically - press any key to pause";
const IPXE_MENU_FOOTER: &str = "cybex-forge - pxe - x86_64 - uefi";

pub fn choose_profile<'a>(
    device: Option<&Device>,
    enabled_profiles: &'a [BootProfile],
) -> ProfileSelection<'a> {
    let Some(device) = device else {
        return ProfileSelection {
            profile: None,
            source: SelectionSource::Menu,
        };
    };

    if let Some(profile_id) = device.one_time_profile_id {
        if let Some(profile) = find_enabled_profile(enabled_profiles, profile_id) {
            return ProfileSelection {
                profile: Some(profile),
                source: SelectionSource::OneTime,
            };
        }
    }

    if let Some(profile_id) = device.default_profile_id {
        if let Some(profile) = find_enabled_profile(enabled_profiles, profile_id) {
            return ProfileSelection {
                profile: Some(profile),
                source: SelectionSource::Assigned,
            };
        }
    }

    ProfileSelection {
        profile: None,
        source: SelectionSource::Menu,
    }
}

pub fn render_menu(
    public_base_url: &str,
    profiles: &[BootProfile],
    mac: Option<&str>,
    serial: Option<&str>,
    timeout_ms: u32,
) -> String {
    let menu_profiles = menu_profiles(profiles);
    let mut script = String::with_capacity(2048 + (menu_profiles.len() * 256));
    script.push_str("#!ipxe\n");
    append_ipxe_menu_theme(&mut script, public_base_url);
    let _ = writeln!(script, "set cybex-title {IPXE_MENU_TITLE}");
    let _ = writeln!(script, "set cybex-subtitle {IPXE_MENU_SUBTITLE}");
    if timeout_ms > 0 {
        let _ = writeln!(script, "set cybex-timeout-copy {IPXE_MENU_TIMEOUT_COPY}");
        let _ = writeln!(script, "set menu-timeout {timeout_ms}");
    }
    script.push_str("menu ${cybex-title}\n");
    script.push_str("item --gap ${cybex-subtitle}\n");
    script.push_str("item --gap\n");
    script.push_str("item --key l local Boot local disk\n");

    for profile in &menu_profiles {
        let _ = writeln!(
            script,
            "item profile_{} {}",
            profile.id,
            ipxe_text(&profile.name)
        );
    }

    script.push_str("item --gap\n");
    if timeout_ms > 0 {
        script.push_str("item --gap ${cybex-timeout-copy}\n");
    }
    let _ = writeln!(script, "item --gap {IPXE_MENU_FOOTER}");
    if timeout_ms > 0 {
        script
            .push_str("choose --timeout ${menu-timeout} --default local selected || goto local\n");
    } else {
        script.push_str("choose --default local selected || goto local\n");
    }
    script.push_str("goto ${selected}\n\n");

    for profile in &menu_profiles {
        let _ = writeln!(script, ":profile_{}", profile.id);
        let _ = writeln!(
            script,
            "chain --autofree {}/boot/select/{}?mac={}&serial={} || goto failed",
            public_base_url.trim_end_matches('/'),
            profile.id,
            query_value(mac, "${mac}"),
            query_value(serial, "${serial}")
        );
        script.push_str("goto end\n\n");
    }

    script.push_str(":local\n");
    script.push_str(&render_local_body());
    script.push_str("\n:failed\n");
    script.push_str("echo Cybex Forge failed to load the selected profile\n");
    script.push_str("sleep 5\n");
    script.push_str("goto local\n\n");
    script.push_str(":end\n");
    script
}

fn menu_profiles(profiles: &[BootProfile]) -> Vec<&BootProfile> {
    let mut profiles: Vec<_> = profiles
        .iter()
        .filter(|profile| {
            profile.enabled
                // One-time profiles are reachable only through a per-MAC
                // binding (network reinstall); keep them out of the menu.
                && !profile.one_time
                && profile.profile_type != BootProfileType::LocalDisk
                && profile_has_boot_action(profile)
        })
        .collect();
    profiles.sort_by_cached_key(|profile| {
        (
            Reverse(profile.is_default),
            profile.name.to_lowercase(),
            profile.id,
        )
    });
    profiles
}

fn append_ipxe_menu_theme(script: &mut String, public_base_url: &str) {
    let background_url = asset_url(public_base_url, IPXE_MENU_BACKGROUND_PATH)
        .expect("built-in PXE menu background path must be safe");
    script.push_str("# Cybex boot menu theme, aligned with the ISO GRUB palette.\n");
    script.push_str(&format!(
        "console --x 1024 --y 864 --picture {background_url} --left 280 --right 280 --top 260 --bottom 140 --depth 32 || console --x 1024 --y 768 --depth 32 || echo Cybex Forge: using firmware text console\n"
    ));
    script.push_str("colour --basic 0 --rgb 0x0e0f12 0\n");
    script.push_str("colour --basic 3 --rgb 0xeb9b46 1\n");
    script.push_str("colour --basic 7 --rgb 0xa4a8b0 2\n");
    script.push_str("colour --basic 6 --rgb 0x6f747d 3\n");
    script.push_str("colour --basic 4 --rgb 0x241a10 4\n");
    script.push_str("colour --basic 1 --rgb 0xdd0034 5\n");
    script.push_str("colour --basic 6 --rgb 0x16b8b8 6\n");
    script.push_str("colour --basic 7 --rgb 0xffffff 7\n");
    script.push_str("cpair --foreground 2 --background 0 0\n");
    script.push_str("cpair --foreground 2 --background 0 1\n");
    script.push_str("cpair --foreground 1 --background 4 2\n");
    script.push_str("cpair --foreground 3 --background 0 3\n");
    script.push_str("cpair --foreground 7 --background 0 4\n");
    script.push_str("cpair --foreground 7 --background 5 5\n");
    script.push_str("cpair --foreground 6 --background 0 6\n");
    script.push_str("cpair --foreground 1 --background 4 7\n");
}

pub fn profile_has_boot_action(profile: &BootProfile) -> bool {
    match profile.profile_type {
        BootProfileType::LocalDisk | BootProfileType::ForgeInstaller => true,
        BootProfileType::CustomIpxe => profile
            .raw_script
            .as_ref()
            .map(|script| !script.trim().is_empty())
            .unwrap_or(false),
    }
}

pub fn render_profile_script(profile: &BootProfile, _public_base_url: &str) -> AppResult<String> {
    let mut script = String::new();
    script.push_str("#!ipxe\n");
    script.push_str(&format!("echo Cybex Forge: {}\n", ipxe_text(&profile.name)));

    match profile.profile_type {
        BootProfileType::LocalDisk => {
            script.push_str(&render_local_body());
        }
        BootProfileType::ForgeInstaller => {
            script.push_str("echo Forge installer profiles require a per-client boot session\n");
            script.push_str("sleep 5\n");
            script.push_str("exit 1\n");
        }
        BootProfileType::CustomIpxe => {
            if let Some(raw_script) = profile
                .raw_script
                .as_ref()
                .filter(|script| !script.trim().is_empty())
            {
                return Ok(ensure_ipxe_header(raw_script));
            }
            script.push_str("echo Custom iPXE profile has no script configured\n");
            script.push_str("sleep 5\nexit 1\n");
        }
    }

    Ok(script)
}

fn render_local_body() -> String {
    let mut script = String::new();
    script.push_str("echo Booting from local disk\n");
    script.push_str("iseq ${platform} efi && goto local_efi || goto local_bios\n");
    script.push_str(":local_efi\n");
    script.push_str("sanboot --drive 0 || goto local_exit\n");
    script.push_str("goto end\n");
    script.push_str(":local_bios\n");
    script.push_str("sanboot --no-describe --drive 0x80 || goto local_exit\n");
    script.push_str("goto end\n");
    script.push_str(":local_exit\n");
    script.push_str("echo Returning failure to firmware for local boot\n");
    script.push_str("exit 1\n");
    script
}

fn find_enabled_profile(profiles: &[BootProfile], id: i64) -> Option<&BootProfile> {
    profiles
        .iter()
        .find(|profile| profile.id == id && profile.enabled && profile_has_boot_action(profile))
}

fn ensure_ipxe_header(script: &str) -> String {
    let trimmed = script.trim_start();
    if trimmed.starts_with("#!ipxe") {
        ensure_trailing_newline(script)
    } else {
        format!("#!ipxe\n{}", ensure_trailing_newline(script))
    }
}

fn ensure_trailing_newline(value: &str) -> String {
    if value.ends_with('\n') {
        value.to_string()
    } else {
        format!("{value}\n")
    }
}

fn ipxe_text(value: &str) -> String {
    value
        .chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect()
}

fn query_value(value: Option<&str>, fallback: &str) -> String {
    value
        .map(|value| urlencoding::encode(value).to_string())
        .unwrap_or_else(|| fallback.to_string())
}

#[cfg(test)]
mod tests {
    use crate::models::{BootProfile, BootProfileType, Device};

    use super::{SelectionSource, choose_profile, render_menu};

    fn profile(id: i64, profile_type: BootProfileType) -> BootProfile {
        BootProfile {
            id,
            managed_profile_id: None,
            name: format!("Profile {id}"),
            description: String::new(),
            profile_type,
            enabled: true,
            is_default: false,
            one_time: false,
            raw_script: None,
            created_at: "now".to_string(),
            updated_at: "now".to_string(),
        }
    }

    fn device(default_profile_id: Option<i64>, one_time_profile_id: Option<i64>) -> Device {
        Device {
            id: 10,
            mac: "aa:bb:cc:dd:ee:ff".to_string(),
            hostname: None,
            serial_number: None,
            last_seen_at: None,
            last_selected_profile_id: None,
            notes: String::new(),
            tags: Vec::new(),
            default_profile_id,
            one_time_profile_id,
            one_time_consumed_at: None,
            created_at: "now".to_string(),
            updated_at: "now".to_string(),
        }
    }

    #[test]
    fn unknown_device_gets_menu() {
        let profiles = vec![profile(1, BootProfileType::LocalDisk)];
        let selection = choose_profile(None, &profiles);
        assert_eq!(selection.source, SelectionSource::Menu);
        assert!(selection.profile.is_none());
    }

    #[test]
    fn one_time_profiles_stay_out_of_the_menu_but_boot_via_binding() {
        let mut reinstall = profile(2, BootProfileType::ForgeInstaller);
        reinstall.name = "Reinstall workstation-01".to_string();
        reinstall.one_time = true;
        let mut enrollment = profile(3, BootProfileType::ForgeInstaller);
        enrollment.name = "Default Enrollment".to_string();
        let profiles = vec![
            profile(1, BootProfileType::LocalDisk),
            reinstall,
            enrollment,
        ];

        let menu = render_menu("http://forge.local", &profiles, None, None, 10_000);
        assert!(!menu.contains("Reinstall workstation-01"));
        assert!(menu.contains("Default Enrollment"));

        let device = device(None, Some(2));
        let selection = choose_profile(Some(&device), &profiles);
        assert_eq!(selection.source, SelectionSource::OneTime);
        assert_eq!(selection.profile.unwrap().id, 2);
    }

    #[test]
    fn one_time_profile_wins_over_assigned_default() {
        let installer = profile(2, BootProfileType::ForgeInstaller);
        let profiles = vec![profile(1, BootProfileType::LocalDisk), installer];
        let device = device(Some(1), Some(2));
        let selection = choose_profile(Some(&device), &profiles);
        assert_eq!(selection.source, SelectionSource::OneTime);
        assert_eq!(selection.profile.unwrap().id, 2);
    }

    #[test]
    fn assigned_profile_auto_selects() {
        let mut local = profile(1, BootProfileType::LocalDisk);
        local.is_default = true;
        let installer = profile(2, BootProfileType::ForgeInstaller);
        let profiles = vec![local, installer];
        let device = device(Some(2), None);
        let selection = choose_profile(Some(&device), &profiles);
        assert_eq!(selection.source, SelectionSource::Assigned);
        assert_eq!(selection.profile.unwrap().id, 2);
    }

    #[test]
    fn global_default_profile_gets_menu_instead_of_auto_boot() {
        let mut installer = profile(2, BootProfileType::ForgeInstaller);
        installer.is_default = true;
        let profiles = vec![profile(1, BootProfileType::LocalDisk), installer];
        let device = device(None, None);

        let selection = choose_profile(Some(&device), &profiles);

        assert_eq!(selection.source, SelectionSource::Menu);
        assert!(selection.profile.is_none());
    }

    #[test]
    fn menu_contains_select_chains_and_orders_local_then_default() {
        let mut installer = profile(2, BootProfileType::ForgeInstaller);
        installer.name = "Default Enrollment".to_string();
        installer.is_default = true;
        let mut other = profile(3, BootProfileType::ForgeInstaller);
        other.name = "Other Installer".to_string();
        let profiles = vec![profile(1, BootProfileType::LocalDisk), other, installer];
        let script = render_menu(
            "http://boot.local:8080",
            &profiles,
            Some("aa:bb:cc:dd:ee:ff"),
            None,
            0,
        );
        assert!(script.starts_with("#!ipxe"));
        assert!(script.contains("chain --autofree http://boot.local:8080/boot/select/2"));
        assert!(script.contains("choose --default local selected || goto local"));
        assert!(!script.contains("choose --timeout"));
        assert!(!script.contains("menu-timeout"));
        assert!(script.contains("iseq ${platform} efi && goto local_efi || goto local_bios"));
        assert!(script.contains("sanboot --drive 0 || goto local_exit"));
        assert!(script.contains("sanboot --no-describe --drive 0x80 || goto local_exit"));
        assert!(script.contains("exit 1"));
        let local_item = script.find("item --key l local Boot local disk").unwrap();
        let default_item = script.find("item profile_2 Default Enrollment").unwrap();
        let other_item = script.find("item profile_3 Other Installer").unwrap();
        assert!(local_item < default_item);
        assert!(default_item < other_item);
    }

    #[test]
    fn menu_includes_cybex_theme() {
        let profiles = vec![profile(1, BootProfileType::LocalDisk)];
        let script = render_menu("http://boot.local:8080", &profiles, None, None, 0);

        assert!(script.contains("set cybex-title CYBEX"));
        assert!(script.contains("set cybex-subtitle PXE BOOT - FORGE BOOT - X86_64 - UEFI"));
        assert!(script.contains(
            "console --x 1024 --y 864 --picture http://boot.local:8080/files/assets/pxe-menu.png --left 280 --right 280 --top 260 --bottom 140 --depth 32"
        ));
        assert!(script.contains("colour --basic 0 --rgb 0x0e0f12 0"));
        assert!(script.contains("colour --basic 3 --rgb 0xeb9b46 1"));
        assert!(script.contains("colour --basic 4 --rgb 0x241a10 4"));
        assert!(script.contains("cpair --foreground 1 --background 4 2"));
        assert!(script.contains("menu ${cybex-title}\n"));
        assert!(script.contains("item --gap ${cybex-subtitle}"));
        assert!(script.contains("item --gap cybex-forge - pxe - x86_64 - uefi"));
        assert!(script.contains("choose --default local selected || goto local"));
        assert!(!script.contains("choose --timeout"));
        assert!(!script.contains("iPXE shell"));
        assert!(!script.contains(":shell"));
    }

    #[test]
    fn configured_menu_timeout_emits_countdown() {
        let profiles = vec![profile(1, BootProfileType::LocalDisk)];
        let script = render_menu("http://boot.local:8080", &profiles, None, None, 8000);

        assert!(script.contains("set menu-timeout 8000"));
        assert!(script.contains("item --gap ${cybex-timeout-copy}"));
        assert!(
            script.contains(
                "choose --timeout ${menu-timeout} --default local selected || goto local"
            )
        );
    }

    #[test]
    fn menu_omits_profiles_without_boot_action() {
        let mut raw = profile(3, BootProfileType::CustomIpxe);
        raw.raw_script = Some("echo custom\n".to_string());
        let profiles = vec![
            profile(1, BootProfileType::LocalDisk),
            raw,
            profile(5, BootProfileType::CustomIpxe),
            profile(6, BootProfileType::ForgeInstaller),
        ];

        let script = render_menu("http://boot.local:8080", &profiles, None, None, 0);

        assert!(script.contains("profile_3"));
        assert!(!script.contains("profile_5"));
        assert!(script.contains("profile_6"));
    }

    #[test]
    fn selection_ignores_profiles_without_boot_action() {
        let mut local = profile(1, BootProfileType::LocalDisk);
        local.is_default = true;
        let profiles = vec![local, profile(2, BootProfileType::CustomIpxe)];
        let device = device(Some(2), None);

        let selection = choose_profile(Some(&device), &profiles);

        assert_eq!(selection.source, SelectionSource::Menu);
        assert!(selection.profile.is_none());
    }

    #[test]
    fn menu_sanitizes_control_characters_in_profile_names() {
        let mut installer = profile(2, BootProfileType::ForgeInstaller);
        installer.name = "Installer\n\x1bshell".to_string();
        let profiles = vec![profile(1, BootProfileType::LocalDisk), installer];

        let script = render_menu("http://boot.local:8080", &profiles, None, None, 0);

        assert!(!script.contains('\x1b'));
        assert!(script.contains("Installer  shell"));
    }
}
