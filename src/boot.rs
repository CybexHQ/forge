use crate::{
    assets::asset_url,
    error::{AppError, AppResult},
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
    let mut script = String::new();
    script.push_str("#!ipxe\n");
    append_ipxe_menu_theme(&mut script, public_base_url);
    script.push_str(&format!("set cybex-subtitle {IPXE_MENU_SUBTITLE}\n"));
    if timeout_ms > 0 {
        script.push_str(&format!(
            "set cybex-timeout-copy {IPXE_MENU_TIMEOUT_COPY}\n"
        ));
        script.push_str(&format!("set menu-timeout {timeout_ms}\n"));
    }
    script.push_str("menu\n");
    script.push_str("item --gap ${cybex-subtitle}\n");
    script.push_str("item --gap\n");
    script.push_str("item --key l local Boot local disk\n");

    let menu_profiles = menu_profiles(profiles);
    for profile in &menu_profiles {
        script.push_str(&format!(
            "item profile_{} {}\n",
            profile.id,
            ipxe_text(&profile.name)
        ));
    }

    script.push_str("item --gap\n");
    if timeout_ms > 0 {
        script.push_str("item --gap ${cybex-timeout-copy}\n");
    }
    script.push_str(&format!("item --gap {IPXE_MENU_FOOTER}\n"));
    if timeout_ms > 0 {
        script
            .push_str("choose --timeout ${menu-timeout} --default local selected || goto local\n");
    } else {
        script.push_str("choose --default local selected || goto local\n");
    }
    script.push_str("goto ${selected}\n\n");

    for profile in &menu_profiles {
        script.push_str(&format!(":profile_{}\n", profile.id));
        script.push_str(&format!(
            "chain {}/boot/select/{}?mac={}&serial={} || goto failed\n",
            public_base_url.trim_end_matches('/'),
            profile.id,
            query_value(mac, "${mac}"),
            query_value(serial, "${serial}")
        ));
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
                && profile.profile_type != BootProfileType::LocalDisk
                && profile_has_boot_action(profile)
        })
        .collect();
    profiles.sort_by(|left, right| {
        right
            .is_default
            .cmp(&left.is_default)
            .then_with(|| left.name.to_lowercase().cmp(&right.name.to_lowercase()))
            .then_with(|| left.id.cmp(&right.id))
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
    if profile
        .raw_script
        .as_ref()
        .map(|script| !script.trim().is_empty())
        .unwrap_or(false)
    {
        return true;
    }
    match profile.profile_type {
        BootProfileType::LocalDisk => true,
        BootProfileType::LinuxInstaller | BootProfileType::IsoLive => {
            profile
                .kernel_path
                .as_ref()
                .map(|path| !path.trim().is_empty())
                .unwrap_or(false)
                || profile
                    .iso_path
                    .as_ref()
                    .map(|path| !path.trim().is_empty())
                    .unwrap_or(false)
        }
        BootProfileType::CustomIpxe => false,
    }
}

pub fn render_profile_script(profile: &BootProfile, public_base_url: &str) -> AppResult<String> {
    if let Some(raw_script) = profile
        .raw_script
        .as_ref()
        .filter(|script| !script.trim().is_empty())
    {
        return Ok(ensure_ipxe_header(raw_script));
    }

    let mut script = String::new();
    script.push_str("#!ipxe\n");
    script.push_str(&format!("echo Cybex Forge: {}\n", ipxe_text(&profile.name)));

    match profile.profile_type {
        BootProfileType::LocalDisk => {
            script.push_str(&render_local_body());
        }
        BootProfileType::LinuxInstaller => {
            if profile.kernel_path.is_some() {
                append_kernel_boot(&mut script, profile, public_base_url)?;
            } else {
                append_iso_registered(&mut script, profile, public_base_url)?;
            }
        }
        BootProfileType::IsoLive => {
            if profile.kernel_path.is_some() {
                append_kernel_boot(&mut script, profile, public_base_url)?;
            } else {
                append_iso_registered(&mut script, profile, public_base_url)?;
            }
        }
        BootProfileType::CustomIpxe => {
            script.push_str("echo Custom iPXE profile has no raw script configured\n");
            script.push_str("sleep 5\n");
            script.push_str("exit 1\n");
        }
    }

    Ok(script)
}

fn append_iso_registered(
    script: &mut String,
    profile: &BootProfile,
    public_base_url: &str,
) -> AppResult<()> {
    if let Some(iso_path) = &profile.iso_path {
        let iso_url = asset_url(public_base_url, iso_path)?;
        script.push_str(&format!("echo ISO registered at {iso_url}\n"));
        script.push_str(
            "echo UEFI iPXE ISO boot needs extracted netboot assets or a raw script override\n",
        );
    } else {
        script.push_str("echo ISO profile has no ISO or netboot assets configured\n");
    }
    script.push_str("sleep 5\n");
    script.push_str("exit 1\n");
    Ok(())
}

fn append_kernel_boot(
    script: &mut String,
    profile: &BootProfile,
    public_base_url: &str,
) -> AppResult<()> {
    let kernel_path = profile.kernel_path.as_deref().ok_or_else(|| {
        AppError::Validation("kernel_path is required for this profile".to_string())
    })?;
    let kernel_url = asset_url(public_base_url, kernel_path)?;
    script.push_str("kernel ");
    script.push_str(&kernel_url);
    if let Some(cmdline) = profile
        .cmdline
        .as_ref()
        .filter(|cmdline| !cmdline.trim().is_empty())
    {
        validate_kernel_cmdline(cmdline)?;
        script.push(' ');
        script.push_str(cmdline.trim());
    }
    script.push('\n');

    if let Some(initrd_path) = profile
        .initrd_path
        .as_ref()
        .filter(|path| !path.trim().is_empty())
    {
        let initrd_url = asset_url(public_base_url, initrd_path)?;
        script.push_str("initrd ");
        script.push_str(&initrd_url);
        script.push('\n');
    }

    script.push_str("boot\n");
    Ok(())
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

fn validate_kernel_cmdline(value: &str) -> AppResult<()> {
    if value.chars().any(char::is_control) {
        return Err(AppError::Validation(
            "kernel cmdline must not contain control characters".to_string(),
        ));
    }
    Ok(())
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

    use super::{SelectionSource, choose_profile, render_menu, render_profile_script};

    fn profile(id: i64, profile_type: BootProfileType) -> BootProfile {
        BootProfile {
            id,
            managed_profile_id: None,
            name: format!("Profile {id}"),
            description: String::new(),
            profile_type,
            installer_iso_source: "boot_profile".to_string(),
            enabled: true,
            is_default: false,
            one_time: false,
            kernel_path: None,
            initrd_path: None,
            iso_path: None,
            cmdline: None,
            raw_script: None,
            desired_iso_artifact_id: String::new(),
            desired_iso_filename: String::new(),
            desired_iso_size_bytes: 0,
            desired_iso_sha256: String::new(),
            desired_iso_built_at: None,
            desired_iso_url: String::new(),
            desired_iso_download_url: String::new(),
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
    fn one_time_profile_wins_over_assigned_default() {
        let mut installer = profile(2, BootProfileType::LinuxInstaller);
        installer.kernel_path = Some("ubuntu/vmlinuz".to_string());
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
        let mut installer = profile(2, BootProfileType::LinuxInstaller);
        installer.kernel_path = Some("ubuntu/vmlinuz".to_string());
        let profiles = vec![local, installer];
        let device = device(Some(2), None);
        let selection = choose_profile(Some(&device), &profiles);
        assert_eq!(selection.source, SelectionSource::Assigned);
        assert_eq!(selection.profile.unwrap().id, 2);
    }

    #[test]
    fn global_default_profile_gets_menu_instead_of_auto_boot() {
        let mut installer = profile(2, BootProfileType::LinuxInstaller);
        installer.is_default = true;
        installer.kernel_path = Some("ubuntu/vmlinuz".to_string());
        let profiles = vec![profile(1, BootProfileType::LocalDisk), installer];
        let device = device(None, None);

        let selection = choose_profile(Some(&device), &profiles);

        assert_eq!(selection.source, SelectionSource::Menu);
        assert!(selection.profile.is_none());
    }

    #[test]
    fn menu_contains_select_chains_and_orders_local_then_default() {
        let mut installer = profile(2, BootProfileType::LinuxInstaller);
        installer.name = "Default Enrollment".to_string();
        installer.is_default = true;
        installer.kernel_path = Some("ubuntu/vmlinuz".to_string());
        let mut other = profile(3, BootProfileType::LinuxInstaller);
        other.name = "Other Installer".to_string();
        other.kernel_path = Some("other/vmlinuz".to_string());
        let profiles = vec![profile(1, BootProfileType::LocalDisk), other, installer];
        let script = render_menu(
            "http://boot.local:8080",
            &profiles,
            Some("aa:bb:cc:dd:ee:ff"),
            None,
            0,
        );
        assert!(script.starts_with("#!ipxe"));
        assert!(script.contains("chain http://boot.local:8080/boot/select/2"));
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
    fn menu_includes_cybex_iso_aligned_theme() {
        let profiles = vec![profile(1, BootProfileType::LocalDisk)];
        let script = render_menu("http://boot.local:8080", &profiles, None, None, 0);

        assert!(!script.contains("set cybex-title CYBEX"));
        assert!(script.contains("set cybex-subtitle PXE BOOT - FORGE BOOT - X86_64 - UEFI"));
        assert!(script.contains(
            "console --x 1024 --y 864 --picture http://boot.local:8080/files/assets/pxe-menu.png --left 280 --right 280 --top 260 --bottom 140 --depth 32"
        ));
        assert!(script.contains("colour --basic 0 --rgb 0x0e0f12 0"));
        assert!(script.contains("colour --basic 3 --rgb 0xeb9b46 1"));
        assert!(script.contains("colour --basic 4 --rgb 0x241a10 4"));
        assert!(script.contains("cpair --foreground 1 --background 4 2"));
        assert!(script.contains("menu\n"));
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
        let mut iso_with_kernel = profile(4, BootProfileType::IsoLive);
        iso_with_kernel.kernel_path = Some("ubuntu/vmlinuz".to_string());
        let mut iso_with_file = profile(6, BootProfileType::IsoLive);
        iso_with_file.iso_path = Some("isos/installer.iso".to_string());
        let profiles = vec![
            profile(1, BootProfileType::LocalDisk),
            profile(2, BootProfileType::IsoLive),
            raw,
            iso_with_kernel,
            profile(5, BootProfileType::CustomIpxe),
            iso_with_file,
        ];

        let script = render_menu("http://boot.local:8080", &profiles, None, None, 0);

        assert!(!script.contains("profile_2"));
        assert!(script.contains("profile_3"));
        assert!(script.contains("profile_4"));
        assert!(!script.contains("profile_5"));
        assert!(script.contains("profile_6"));
    }

    #[test]
    fn selection_ignores_profiles_without_boot_action() {
        let mut local = profile(1, BootProfileType::LocalDisk);
        local.is_default = true;
        let profiles = vec![local, profile(2, BootProfileType::IsoLive)];
        let device = device(Some(2), None);

        let selection = choose_profile(Some(&device), &profiles);

        assert_eq!(selection.source, SelectionSource::Menu);
        assert!(selection.profile.is_none());
    }

    #[test]
    fn menu_sanitizes_control_characters_in_profile_names() {
        let mut installer = profile(2, BootProfileType::LinuxInstaller);
        installer.name = "Installer\n\x1bshell".to_string();
        installer.kernel_path = Some("ubuntu/vmlinuz".to_string());
        let profiles = vec![profile(1, BootProfileType::LocalDisk), installer];

        let script = render_menu("http://boot.local:8080", &profiles, None, None, 0);

        assert!(!script.contains('\x1b'));
        assert!(script.contains("Installer  shell"));
    }

    #[test]
    fn linux_installer_renders_kernel_initrd_boot() {
        let mut linux = profile(2, BootProfileType::LinuxInstaller);
        linux.kernel_path = Some("ubuntu/vmlinuz".to_string());
        linux.initrd_path = Some("ubuntu/initrd.img".to_string());
        linux.cmdline = Some("auto=true".to_string());
        let script = render_profile_script(&linux, "http://boot.local:8080").unwrap();
        assert!(script.contains("kernel http://boot.local:8080/files/ubuntu/vmlinuz auto=true"));
        assert!(script.contains("initrd http://boot.local:8080/files/ubuntu/initrd.img"));
        assert!(script.contains("boot"));
    }

    #[test]
    fn linux_installer_rejects_control_characters_in_cmdline() {
        let mut linux = profile(2, BootProfileType::LinuxInstaller);
        linux.kernel_path = Some("ubuntu/vmlinuz".to_string());
        linux.cmdline = Some("auto=true\nshell".to_string());

        let err = render_profile_script(&linux, "http://boot.local:8080").unwrap_err();

        assert!(err.to_string().contains("kernel cmdline"));
    }
}
