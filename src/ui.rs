use std::str::FromStr;

use axum::{
    extract::{Form, Path, State},
    response::{Html, Response},
};
use maud::{DOCTYPE, Markup, PreEscaped, html};
use serde::Deserialize;

use crate::{
    AppState,
    assets::{self, redirect_to},
    db,
    error::{AppError, AppResult},
    models::{
        BootProfile, BootProfileType, CreateBootProfileRequest, CreateDeviceRequest, IsoAsset,
        UpdateBootProfileRequest, UpdateDeviceRequest,
    },
};

const CSS: &str = r#"
:root {
  --bg: #f6f7f8;
  --surface: #ffffff;
  --line: #d9dee3;
  --ink: #202428;
  --muted: #66727d;
  --sidebar: #23272b;
  --sidebar-ink: #f5f7f8;
  --accent: #007c89;
  --accent-soft: #d9f2f4;
  --warn: #a05a00;
  --danger: #9f2a2a;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--ink);
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  font-size: 14px;
  line-height: 1.45;
}
a { color: inherit; text-decoration: none; }
.shell { min-height: 100vh; display: grid; grid-template-columns: 240px 1fr; }
.sidebar { background: var(--sidebar); color: var(--sidebar-ink); padding: 22px 18px; }
.brand { font-size: 18px; font-weight: 700; margin-bottom: 28px; }
.nav { display: grid; gap: 6px; }
.nav a, .logout {
  display: block;
  width: 100%;
  border: 0;
  border-radius: 6px;
  padding: 10px 12px;
  background: transparent;
  color: #d7dcdf;
  text-align: left;
  font: inherit;
  cursor: pointer;
}
.nav a.active, .nav a:hover, .logout:hover { background: rgba(255,255,255,.1); color: #fff; }
.main { min-width: 0; }
.topbar {
  height: 64px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 28px;
  border-bottom: 1px solid var(--line);
  background: var(--surface);
}
.topbar h1 { margin: 0; font-size: 20px; }
.content { padding: 26px 28px 42px; display: grid; gap: 22px; }
.metrics { display: grid; grid-template-columns: repeat(4, minmax(150px, 1fr)); gap: 12px; }
.metric, .panel {
  background: var(--surface);
  border: 1px solid var(--line);
  border-radius: 8px;
}
.metric { padding: 16px; }
.metric .value { font-size: 28px; font-weight: 700; }
.metric .label { color: var(--muted); }
.panel { overflow: clip; }
.panel h2 { margin: 0; padding: 16px 18px; font-size: 16px; border-bottom: 1px solid var(--line); }
.panel-body { padding: 18px; }
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; background: var(--surface); }
th, td { padding: 11px 12px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; }
th { color: var(--muted); font-size: 12px; text-transform: uppercase; font-weight: 700; }
tr:last-child td { border-bottom: 0; }
.muted { color: var(--muted); }
.tag { display: inline-block; padding: 2px 7px; border-radius: 999px; background: var(--accent-soft); color: #00565f; margin: 0 4px 4px 0; font-size: 12px; }
.status { font-weight: 700; color: var(--accent); }
.status.off { color: var(--muted); }
.form-grid { display: grid; grid-template-columns: repeat(3, minmax(180px, 1fr)); gap: 12px; align-items: end; }
.form-grid.wide { grid-template-columns: repeat(2, minmax(220px, 1fr)); }
.row-form { display: grid; grid-template-columns: repeat(2, minmax(160px, 1fr)); gap: 10px; min-width: 420px; }
label { display: grid; gap: 5px; color: var(--muted); font-size: 12px; font-weight: 700; text-transform: uppercase; }
input, select, textarea {
  width: 100%;
  border: 1px solid var(--line);
  border-radius: 6px;
  padding: 9px 10px;
  background: #fff;
  color: var(--ink);
  font: inherit;
}
textarea { min-height: 74px; resize: vertical; }
.checks { display: flex; gap: 14px; align-items: center; flex-wrap: wrap; color: var(--muted); }
.checks label { display: flex; grid-template-columns: none; align-items: center; gap: 6px; text-transform: none; font-weight: 600; }
.checks input { width: auto; }
.actions { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
button, .button {
  border: 1px solid #006a75;
  border-radius: 6px;
  background: var(--accent);
  color: #fff;
  padding: 9px 12px;
  font: inherit;
  font-weight: 700;
  cursor: pointer;
}
button.secondary { background: #fff; color: var(--accent); }
.login {
  min-height: 100vh;
  display: grid;
  place-items: center;
  padding: 24px;
}
.login-box {
  width: min(420px, 100%);
  background: var(--surface);
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: 24px;
}
.login-box h1 { margin: 0 0 18px; }
.error { color: var(--danger); font-weight: 700; }
code {
  display: inline-block;
  background: #eef1f3;
  border: 1px solid var(--line);
  border-radius: 6px;
  padding: 2px 6px;
}
@media (max-width: 900px) {
  .shell { grid-template-columns: 1fr; }
  .sidebar { position: static; }
  .metrics, .form-grid, .form-grid.wide { grid-template-columns: 1fr; }
  .row-form { grid-template-columns: 1fr; min-width: 260px; }
}
"#;

pub fn render_login(error: Option<&str>) -> Html<String> {
    Html(
        html! {
            (DOCTYPE)
            html lang="en" {
                head {
                    meta charset="utf-8";
                    meta name="viewport" content="width=device-width, initial-scale=1";
                    title { "Cybex Forge" }
                    style { (PreEscaped(CSS)) }
                }
                body {
                    main class="login" {
                        section class="login-box" {
                            h1 { "Cybex Forge" }
                            @if let Some(error) = error {
                                p class="error" { (error) }
                            }
                            form method="post" action="/login" {
                                label {
                                    "Admin token"
                                    input type="password" name="token" autocomplete="current-password" autofocus;
                                }
                                div class="actions" style="margin-top:16px" {
                                    button type="submit" { "Sign in" }
                                }
                            }
                        }
                    }
                }
            }
        }
        .into_string(),
    )
}

pub async fn dashboard(State(state): State<AppState>) -> AppResult<Html<String>> {
    let events = db::list_boot_events(&state.db, 20).await?;
    let devices = db::list_devices(&state.db).await?;
    let profiles = db::list_profiles(&state.db).await?;
    let isos = db::list_iso_assets(&state.db).await?;

    Ok(layout(
        "Dashboard",
        "dashboard",
        html! {
            div class="metrics" {
                (metric("Devices", devices.len()))
                (metric("Profiles", profiles.len()))
                (metric("ISOs", isos.len()))
                (metric("Recent boots", events.len()))
            }
            section class="panel" {
                h2 { "Recent PXE boot attempts" }
                (events_table(&events))
            }
        },
    ))
}

pub async fn devices_page(State(state): State<AppState>) -> AppResult<Html<String>> {
    let devices = db::list_devices(&state.db).await?;
    let profiles = db::list_profiles(&state.db).await?;

    Ok(layout(
        "Devices",
        "devices",
        html! {
            section class="panel" {
                h2 { "Register device" }
                div class="panel-body" {
                    form method="post" action="/devices" class="form-grid" {
                        label { "MAC" input name="mac" placeholder="aa:bb:cc:dd:ee:ff" required; }
                        label { "Hostname" input name="hostname"; }
                        label { "Serial" input name="serial_number"; }
                        label { "Tags" input name="tags" placeholder="lab, proxmox"; }
                        label { "Default profile" (profile_select("default_profile_id", None, &profiles, true)) }
                        label { "One-time profile" (profile_select("one_time_profile_id", None, &profiles, true)) }
                        div class="actions" { button type="submit" { "Create" } }
                    }
                }
            }
            section class="panel" {
                h2 { "Known devices" }
                div class="table-wrap" {
                    table {
                        thead {
                            tr {
                                th { "MAC" } th { "Host" } th { "Serial" } th { "Last seen" } th { "Tags" } th { "Boot control" }
                            }
                        }
                        tbody {
                            @for device in &devices {
                                tr {
                                    td { code { (&device.mac) } }
                                    td { (optional_text(device.hostname.as_deref())) }
                                    td { (optional_text(device.serial_number.as_deref())) }
                                    td { (optional_text(device.last_seen_at.as_deref())) }
                                    td { (tags_markup(&device.tags)) }
                                    td {
                                        form method="post" action=(format!("/devices/{}", device.id)) class="row-form" {
                                            label { "Hostname" input name="hostname" value=(device.hostname.as_deref().unwrap_or("")); }
                                            label { "Serial" input name="serial_number" value=(device.serial_number.as_deref().unwrap_or("")); }
                                            label { "Tags" input name="tags" value=(device.tags.join(", ")); }
                                            label { "Default" (profile_select("default_profile_id", device.default_profile_id, &profiles, true)) }
                                            label { "One-time" (profile_select("one_time_profile_id", device.one_time_profile_id, &profiles, true)) }
                                            label { "Notes" textarea name="notes" { (&device.notes) } }
                                            div class="actions" { button type="submit" { "Save" } }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
    ))
}

pub async fn profiles_page(State(state): State<AppState>) -> AppResult<Html<String>> {
    let profiles = db::list_profiles(&state.db).await?;

    Ok(layout(
        "Boot Profiles",
        "profiles",
        html! {
            section class="panel" {
                h2 { "Create profile" }
                div class="panel-body" {
                    form method="post" action="/profiles" class="form-grid wide" {
                        label { "Name" input name="name" required; }
                        label { "Type" (profile_type_select("profile_type", BootProfileType::LinuxInstaller)) }
                        label { "Description" input name="description"; }
                        label { "Kernel path" input name="kernel_path" placeholder="netboot/ubuntu/vmlinuz"; }
                        label { "Initrd path" input name="initrd_path" placeholder="netboot/ubuntu/initrd.img"; }
                        label { "ISO path" input name="iso_path" placeholder="isos/example.iso"; }
                        label { "Cmdline" input name="cmdline"; }
                        div class="checks" {
                            label { input type="checkbox" name="enabled" checked; "Enabled" }
                            label { input type="checkbox" name="is_default"; "Default" }
                            label { input type="checkbox" name="one_time"; "One-time capable" }
                        }
                        label { "Raw iPXE script" textarea name="raw_script" {} }
                        div class="actions" { button type="submit" { "Create" } }
                    }
                }
            }
            section class="panel" {
                h2 { "Profiles" }
                div class="table-wrap" {
                    table {
                        thead {
                            tr {
                                th { "Profile" } th { "State" } th { "Type" } th { "Paths" } th { "Edit" }
                            }
                        }
                        tbody {
                            @for profile in &profiles {
                                tr {
                                    td {
                                        strong { (&profile.name) }
                                        div class="muted" { (&profile.description) }
                                    }
                                    td {
                                        @if profile.enabled { span class="status" { "Enabled" } } @else { span class="status off" { "Disabled" } }
                                        @if profile.is_default { div class="tag" { "default" } }
                                        @if profile.one_time { div class="tag" { "one-time" } }
                                    }
                                    td { code { (profile.profile_type.as_str()) } }
                                    td {
                                        (path_line("kernel", profile.kernel_path.as_deref()))
                                        (path_line("initrd", profile.initrd_path.as_deref()))
                                        (path_line("iso", profile.iso_path.as_deref()))
                                    }
                                    td {
                                        form method="post" action=(format!("/profiles/{}", profile.id)) class="row-form" {
                                            label { "Name" input name="name" value=(&profile.name) required; }
                                            label { "Type" (profile_type_select("profile_type", profile.profile_type)) }
                                            label { "Description" input name="description" value=(&profile.description); }
                                            label { "Kernel" input name="kernel_path" value=(profile.kernel_path.as_deref().unwrap_or("")); }
                                            label { "Initrd" input name="initrd_path" value=(profile.initrd_path.as_deref().unwrap_or("")); }
                                            label { "ISO" input name="iso_path" value=(profile.iso_path.as_deref().unwrap_or("")); }
                                            label { "Cmdline" input name="cmdline" value=(profile.cmdline.as_deref().unwrap_or("")); }
                                            label { "Raw script" textarea name="raw_script" { (profile.raw_script.as_deref().unwrap_or("")) } }
                                            div class="checks" {
                                                label { input type="checkbox" name="enabled" checked[profile.enabled]; "Enabled" }
                                                label { input type="checkbox" name="is_default" checked[profile.is_default]; "Default" }
                                                label { input type="checkbox" name="one_time" checked[profile.one_time]; "One-time capable" }
                                            }
                                            div class="actions" { button type="submit" { "Save" } }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
    ))
}

pub async fn isos_page(State(state): State<AppState>) -> AppResult<Html<String>> {
    let isos = db::list_iso_assets(&state.db).await?;

    Ok(layout(
        "ISO / Assets",
        "isos",
        html! {
            section class="panel" {
                h2 { "ISO registry" }
                div class="panel-body" {
                    form method="post" action="/isos" class="actions" {
                        button type="submit" { "Scan ISO directory" }
                        code { (state.config.paths.iso_dir.display()) }
                    }
                }
                (isos_table(&isos))
            }
        },
    ))
}

pub async fn settings_page(State(state): State<AppState>) -> AppResult<Html<String>> {
    let option_66 = option_66_value(state.config.public_base_url());
    let chain = format!("{}/boot/${{mac}}", state.config.public_base_url());

    Ok(layout(
        "Settings",
        "settings",
        html! {
            section class="panel" {
                h2 { "DHCP and paths" }
                div class="panel-body" {
                    table {
                        tbody {
                            tr { th { "UniFi DHCP Option 66" } td { code { (option_66) } } }
                            tr { th { "UniFi DHCP Option 67" } td { code { (&state.config.boot.bootloader_filename) } } }
                            tr { th { "Example iPXE chain" } td { code { (chain) } } }
                            tr { th { "Database" } td { code { (state.config.paths.database_path.display()) } } }
                            tr { th { "Boot assets" } td { code { (state.config.paths.boot_assets_dir.display()) } } }
                            tr { th { "ISOs" } td { code { (state.config.paths.iso_dir.display()) } } }
                            tr { th { "TFTP files" } td { code { (state.config.paths.tftp_dir.display()) } } }
                        }
                    }
                }
            }
        },
    ))
}

#[derive(Debug, Deserialize)]
pub struct DeviceForm {
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub serial_number: Option<String>,
    pub notes: Option<String>,
    pub tags: Option<String>,
    pub default_profile_id: Option<String>,
    pub one_time_profile_id: Option<String>,
}

pub async fn create_device_form(
    State(state): State<AppState>,
    Form(form): Form<DeviceForm>,
) -> AppResult<Response> {
    let mac = form
        .mac
        .ok_or_else(|| AppError::Validation("MAC address is required".to_string()))?;
    db::create_device(
        &state.db,
        CreateDeviceRequest {
            mac,
            hostname: form.hostname,
            serial_number: form.serial_number,
            notes: form.notes,
            tags: Some(split_tags(form.tags)),
            default_profile_id: parse_optional_id(form.default_profile_id)?,
            one_time_profile_id: parse_optional_id(form.one_time_profile_id)?,
        },
    )
    .await?;
    Ok(redirect_to("/devices"))
}

pub async fn update_device_form(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Form(form): Form<DeviceForm>,
) -> AppResult<Response> {
    db::update_device(
        &state.db,
        id,
        UpdateDeviceRequest {
            hostname: Some(form.hostname),
            serial_number: Some(form.serial_number),
            notes: Some(form.notes.unwrap_or_default()),
            tags: Some(split_tags(form.tags)),
            default_profile_id: Some(parse_optional_id(form.default_profile_id)?),
            one_time_profile_id: Some(parse_optional_id(form.one_time_profile_id)?),
        },
    )
    .await?;
    Ok(redirect_to("/devices"))
}

#[derive(Debug, Deserialize)]
pub struct ProfileForm {
    pub name: String,
    pub description: Option<String>,
    pub profile_type: String,
    pub enabled: Option<String>,
    pub is_default: Option<String>,
    pub one_time: Option<String>,
    pub kernel_path: Option<String>,
    pub initrd_path: Option<String>,
    pub iso_path: Option<String>,
    pub cmdline: Option<String>,
    pub raw_script: Option<String>,
}

pub async fn create_profile_form(
    State(state): State<AppState>,
    Form(form): Form<ProfileForm>,
) -> AppResult<Response> {
    db::create_profile(&state.db, form.into_create_request()?).await?;
    Ok(redirect_to("/profiles"))
}

pub async fn update_profile_form(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Form(form): Form<ProfileForm>,
) -> AppResult<Response> {
    db::update_profile(&state.db, id, form.into_update_request()?).await?;
    Ok(redirect_to("/profiles"))
}

pub async fn scan_isos_form(State(state): State<AppState>) -> AppResult<Response> {
    assets::scan_iso_dir(&state.config, &state.db).await?;
    Ok(redirect_to("/isos"))
}

impl ProfileForm {
    fn into_create_request(self) -> AppResult<CreateBootProfileRequest> {
        Ok(CreateBootProfileRequest {
            name: self.name,
            description: self.description,
            profile_type: BootProfileType::from_str(&self.profile_type)?,
            enabled: Some(self.enabled.is_some()),
            is_default: Some(self.is_default.is_some()),
            one_time: Some(self.one_time.is_some()),
            kernel_path: self.kernel_path,
            initrd_path: self.initrd_path,
            iso_path: self.iso_path,
            cmdline: self.cmdline,
            raw_script: self.raw_script,
        })
    }

    fn into_update_request(self) -> AppResult<UpdateBootProfileRequest> {
        Ok(UpdateBootProfileRequest {
            name: Some(self.name),
            description: self.description,
            profile_type: Some(BootProfileType::from_str(&self.profile_type)?),
            enabled: Some(self.enabled.is_some()),
            is_default: Some(self.is_default.is_some()),
            one_time: Some(self.one_time.is_some()),
            kernel_path: Some(self.kernel_path),
            initrd_path: Some(self.initrd_path),
            iso_path: Some(self.iso_path),
            cmdline: Some(self.cmdline),
            raw_script: Some(self.raw_script),
        })
    }
}

fn layout(title: &str, active: &str, content: Markup) -> Html<String> {
    Html(
        html! {
            (DOCTYPE)
            html lang="en" {
                head {
                    meta charset="utf-8";
                    meta name="viewport" content="width=device-width, initial-scale=1";
                    title { (title) " - Cybex Forge" }
                    style { (PreEscaped(CSS)) }
                }
                body {
                    div class="shell" {
                        aside class="sidebar" {
                            div class="brand" { "Cybex Forge" }
                            nav class="nav" {
                                (nav_link("/", "Dashboard", active == "dashboard"))
                                (nav_link("/devices", "Devices", active == "devices"))
                                (nav_link("/profiles", "Boot Profiles", active == "profiles"))
                                (nav_link("/isos", "ISO / Assets", active == "isos"))
                                (nav_link("/settings", "Settings", active == "settings"))
                                form method="post" action="/logout" { button class="logout" type="submit" { "Sign out" } }
                            }
                        }
                        main class="main" {
                            header class="topbar" {
                                h1 { (title) }
                            }
                            div class="content" {
                                (content)
                            }
                        }
                    }
                }
            }
        }
        .into_string(),
    )
}

fn nav_link(href: &str, label: &str, active: bool) -> Markup {
    html! {
        a href=(href) class=(if active { "active" } else { "" }) { (label) }
    }
}

fn metric(label: &str, value: usize) -> Markup {
    html! {
        div class="metric" {
            div class="value" { (value) }
            div class="label" { (label) }
        }
    }
}

fn events_table(events: &[crate::models::BootEvent]) -> Markup {
    html! {
        div class="table-wrap" {
            table {
                thead {
                    tr { th { "Time" } th { "MAC" } th { "IP" } th { "Profile" } th { "Known" } th { "User agent" } }
                }
                tbody {
                    @for event in events {
                        tr {
                            td { (&event.created_at) }
                            td { (optional_text(event.mac.as_deref())) }
                            td { (optional_text(event.ip_address.as_deref())) }
                            td { (optional_text(event.selected_profile_name.as_deref())) }
                            td { @if event.known_device { "yes" } @else { "no" } }
                            td { (optional_text(event.user_agent.as_deref())) }
                        }
                    }
                }
            }
        }
    }
}

fn isos_table(isos: &[IsoAsset]) -> Markup {
    html! {
        div class="table-wrap" {
            table {
                thead {
                    tr { th { "File" } th { "Size" } th { "SHA-256" } th { "Scanned" } }
                }
                tbody {
                    @for iso in isos {
                        tr {
                            td { code { (&iso.relative_path) } }
                            td { (format_bytes(iso.size_bytes)) }
                            td { code { (&iso.checksum_sha256) } }
                            td { (&iso.last_scanned_at) }
                        }
                    }
                }
            }
        }
    }
}

fn tags_markup(tags: &[String]) -> Markup {
    html! {
        @if tags.is_empty() {
            span class="muted" { "-" }
        } @else {
            @for tag in tags {
                span class="tag" { (tag) }
            }
        }
    }
}

fn profile_select(
    name: &str,
    selected: Option<i64>,
    profiles: &[BootProfile],
    include_none: bool,
) -> Markup {
    html! {
        select name=(name) {
            @if include_none {
                option value="" selected[selected.is_none()] { "None" }
            }
            @for profile in profiles {
                option value=(profile.id) selected[selected == Some(profile.id)] { (&profile.name) }
            }
        }
    }
}

fn profile_type_select(name: &str, selected: BootProfileType) -> Markup {
    let values = [
        (BootProfileType::LocalDisk, "local_disk"),
        (BootProfileType::IsoLive, "iso_live"),
        (BootProfileType::LinuxInstaller, "linux_installer"),
        (BootProfileType::CustomIpxe, "custom_ipxe"),
    ];
    html! {
        select name=(name) {
            @for (value, label) in values {
                option value=(label) selected[value == selected] { (label) }
            }
        }
    }
}

fn optional_text(value: Option<&str>) -> Markup {
    html! {
        @if let Some(value) = value.filter(|value| !value.is_empty()) {
            (value)
        } @else {
            span class="muted" { "-" }
        }
    }
}

fn path_line(label: &str, value: Option<&str>) -> Markup {
    html! {
        @if let Some(value) = value {
            div { span class="muted" { (label) ": " } code { (value) } }
        }
    }
}

fn split_tags(tags: Option<String>) -> Vec<String> {
    tags.unwrap_or_default()
        .split(',')
        .map(|tag| tag.trim().to_string())
        .filter(|tag| !tag.is_empty())
        .collect()
}

fn parse_optional_id(value: Option<String>) -> AppResult<Option<i64>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    trimmed
        .parse::<i64>()
        .map(Some)
        .map_err(|_| AppError::Validation(format!("invalid id '{trimmed}'")))
}

fn format_bytes(size: i64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = size as f64;
    let mut unit = 0usize;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{} {}", size, UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn option_66_value(public_base_url: &str) -> String {
    public_base_url
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .split('/')
        .next()
        .unwrap_or(public_base_url)
        .split(':')
        .next()
        .unwrap_or(public_base_url)
        .to_string()
}
