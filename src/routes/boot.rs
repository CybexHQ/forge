use std::net::{IpAddr, SocketAddr};

use axum::{
    extract::{ConnectInfo, Path, Query, State},
    http::{HeaderMap, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;

use crate::{
    AppState, boot as boot_logic, db,
    error::{AppError, AppResult},
    models::{BootProfile, BootProfileType, Device, NewBootEvent, normalize_mac},
};

const MAX_BOOT_SERIAL_LEN: usize = 128;
const MAX_BOOT_USER_AGENT_LEN: usize = 256;

#[derive(Debug, Deserialize)]
pub struct BootQuery {
    pub mac: Option<String>,
    pub serial: Option<String>,
    pub cybex_check: Option<String>,
}

pub async fn boot_root(
    State(state): State<AppState>,
    Query(query): Query<BootQuery>,
    headers: HeaderMap,
    connect: Option<ConnectInfo<SocketAddr>>,
) -> AppResult<Response> {
    let checker = is_local_checker_request(&query, &headers, connect.as_ref().map(|value| value.0));
    let script = build_boot_script(
        &state,
        query.mac,
        query.serial,
        &headers,
        connect.map(|value| value.0),
        checker,
    )
    .await?;
    Ok(ipxe_response(script))
}

pub async fn boot_mac(
    State(state): State<AppState>,
    Path(mac): Path<String>,
    Query(query): Query<BootQuery>,
    headers: HeaderMap,
    connect: Option<ConnectInfo<SocketAddr>>,
) -> AppResult<Response> {
    let checker = is_local_checker_request(&query, &headers, connect.as_ref().map(|value| value.0));
    let script = build_boot_script(
        &state,
        Some(mac),
        query.serial,
        &headers,
        connect.map(|value| value.0),
        checker,
    )
    .await?;
    Ok(ipxe_response(script))
}

pub async fn boot_serial(
    State(state): State<AppState>,
    Path(serial): Path<String>,
    Query(query): Query<BootQuery>,
    headers: HeaderMap,
    connect: Option<ConnectInfo<SocketAddr>>,
) -> AppResult<Response> {
    let checker = is_local_checker_request(&query, &headers, connect.as_ref().map(|value| value.0));
    let script = build_boot_script(
        &state,
        query.mac,
        Some(serial),
        &headers,
        connect.map(|value| value.0),
        checker,
    )
    .await?;
    Ok(ipxe_response(script))
}

pub async fn boot_select_profile(
    State(state): State<AppState>,
    Path(profile_id): Path<String>,
    Query(query): Query<BootQuery>,
    headers: HeaderMap,
    connect: Option<ConnectInfo<SocketAddr>>,
) -> AppResult<Response> {
    let profile_id = boot_profile_id_from_path(&profile_id)?;
    let profile = db::get_profile(&state.db, profile_id).await?;
    if !profile.enabled || !boot_logic::profile_has_boot_action(&profile) {
        return Err(AppError::NotFound);
    }

    let mut device: Option<Device> = None;
    let mut known_device = false;
    let checker = is_local_checker_request(&query, &headers, connect.as_ref().map(|value| value.0));
    let mac = normalized_optional_mac(query.mac)?;
    let serial = clean_optional(query.serial);

    if !checker {
        if let Some(mac) = mac.as_deref() {
            let (seen_device, was_known) =
                db::upsert_seen_device(&state.db, mac, serial.as_deref()).await?;
            known_device = was_known;
            db::set_device_last_selected(&state.db, seen_device.id, profile.id).await?;
            device = Some(seen_device);
        } else if let Some(serial) = serial.as_deref() {
            if let Some(found) = db::get_device_by_serial(&state.db, serial).await? {
                let touched = db::touch_device_seen(&state.db, found.id).await?;
                db::set_device_last_selected(&state.db, touched.id, profile.id).await?;
                known_device = true;
                device = Some(touched);
            }
        }
    }

    let selected_mac = mac
        .as_deref()
        .or_else(|| device.as_ref().map(|device| device.mac.as_str()));
    let script = render_selected_profile(&state, &profile, selected_mac, device.as_ref()).await?;

    if !checker {
        db::insert_boot_event(
            &state.db,
            NewBootEvent {
                device_id: device.as_ref().map(|device| device.id),
                mac: mac.or_else(|| device.as_ref().map(|device| device.mac.clone())),
                serial_number: serial.or_else(|| {
                    device
                        .as_ref()
                        .and_then(|device| device.serial_number.clone())
                }),
                ip_address: remote_ip(connect.map(|value| value.0), &headers),
                user_agent: user_agent(&headers),
                selected_profile_id: Some(profile.id),
                selected_profile_name: Some(profile.name.clone()),
                known_device,
            },
        )
        .await?;
    }

    Ok(ipxe_response(script))
}

pub async fn boot_kexec(
    State(state): State<AppState>,
    Path(mac): Path<String>,
) -> AppResult<Response> {
    let mac = normalize_mac(&mac)?;
    let device = db::get_device_by_mac(&state.db, &mac)
        .await?
        .ok_or(AppError::NotFound)?;
    let profile_id = device.one_time_profile_id.ok_or(AppError::NotFound)?;
    let profile = db::get_profile(&state.db, profile_id).await?;
    if !profile.enabled || profile.profile_type != BootProfileType::PulseInstaller {
        return Err(AppError::NotFound);
    }
    let launch = create_installer_launch(&state, &profile, &device.mac, Some(&device)).await?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "no-store, max-age=0"),
            (header::PRAGMA, "no-cache"),
        ],
        axum::Json(launch),
    )
        .into_response())
}

async fn build_boot_script(
    state: &AppState,
    mac: Option<String>,
    serial: Option<String>,
    headers: &HeaderMap,
    connect: Option<SocketAddr>,
    checker: bool,
) -> AppResult<String> {
    let mac = normalized_optional_mac(mac)?;
    let serial = clean_optional(serial);
    let mut known_device = false;
    let mut device = None;

    if !checker {
        if let Some(mac) = mac.as_deref() {
            let (seen_device, was_known) =
                db::upsert_seen_device(&state.db, mac, serial.as_deref()).await?;
            known_device = was_known;
            device = Some(seen_device);
        } else if let Some(serial) = serial.as_deref() {
            if let Some(found) = db::get_device_by_serial(&state.db, serial).await? {
                let touched = db::touch_device_seen(&state.db, found.id).await?;
                known_device = true;
                device = Some(touched);
            }
        }
    }

    let profiles = db::list_enabled_profiles(&state.db).await?;
    let selection_device = if known_device { device.as_ref() } else { None };
    let selection = boot_logic::choose_profile(selection_device, &profiles);

    let selected_profile = selection.profile.cloned();
    let selected_script = if let Some(profile) = selected_profile.as_ref() {
        let selected_mac = mac
            .as_deref()
            .or_else(|| device.as_ref().map(|device| device.mac.as_str()));
        Some(render_selected_profile(state, profile, selected_mac, device.as_ref()).await?)
    } else {
        None
    };

    if !checker {
        if let (Some(device), Some(profile)) = (device.as_ref(), selected_profile.as_ref()) {
            match selection.source {
                boot_logic::SelectionSource::OneTime => {
                    db::consume_one_time_profile(&state.db, device.id, profile.id).await?;
                }
                boot_logic::SelectionSource::Assigned => {
                    db::set_device_last_selected(&state.db, device.id, profile.id).await?;
                }
                boot_logic::SelectionSource::Menu => {}
            }
        }
    }

    if !checker {
        db::insert_boot_event(
            &state.db,
            NewBootEvent {
                device_id: device.as_ref().map(|device| device.id),
                mac: mac
                    .clone()
                    .or_else(|| device.as_ref().map(|device| device.mac.clone())),
                serial_number: serial.clone().or_else(|| {
                    device
                        .as_ref()
                        .and_then(|device| device.serial_number.clone())
                }),
                ip_address: remote_ip(connect, headers),
                user_agent: user_agent(headers),
                selected_profile_id: selected_profile.as_ref().map(|profile| profile.id),
                selected_profile_name: selected_profile
                    .as_ref()
                    .map(|profile| profile.name.clone()),
                known_device,
            },
        )
        .await?;
    }

    if selected_profile.is_some() {
        Ok(selected_script.expect("selected profile has a rendered script"))
    } else {
        let runtime = state.runtime_settings();
        Ok(boot_logic::render_menu(
            &runtime.public_base_url,
            &profiles,
            mac.as_deref(),
            serial.as_deref(),
            runtime.menu_timeout_ms,
        ))
    }
}

async fn render_selected_profile(
    state: &AppState,
    profile: &BootProfile,
    mac: Option<&str>,
    device: Option<&Device>,
) -> AppResult<String> {
    if profile.profile_type != BootProfileType::PulseInstaller {
        let runtime = state.runtime_settings();
        return boot_logic::render_profile_script(profile, &runtime.public_base_url);
    }
    let mac = mac.ok_or_else(|| {
        AppError::Validation("a normalized MAC is required for Pulse installer boot".to_string())
    })?;
    let launch = create_installer_launch(state, profile, mac, device).await?;
    Ok(crate::netboot::render_ipxe_launch(&launch))
}

async fn create_installer_launch(
    state: &AppState,
    profile: &BootProfile,
    mac: &str,
    device: Option<&Device>,
) -> AppResult<crate::netboot::BootSessionLaunch> {
    let profile_id = profile.managed_profile_id.as_deref().ok_or_else(|| {
        AppError::Config("Pulse installer profile has no managed identity".to_string())
    })?;
    let binding: Option<(Option<String>, Option<String>)> = if let Some(device) = device {
        sqlx::query_as("SELECT managed_device_id, reinstall_request_id FROM devices WHERE id = ?")
            .bind(device.id)
            .fetch_optional(&state.db)
            .await?
    } else {
        None
    };
    crate::netboot::create_boot_session(
        state,
        mac,
        Some(profile_id),
        binding.as_ref().and_then(|value| value.0.as_deref()),
        binding.as_ref().and_then(|value| value.1.as_deref()),
    )
    .await
    .map_err(|_| AppError::Config("could not create signed Pulse boot session".to_string()))
}

fn normalized_optional_mac(mac: Option<String>) -> AppResult<Option<String>> {
    mac.map(|mac| normalize_mac(&mac)).transpose()
}

fn boot_profile_id_from_path(value: &str) -> AppResult<i64> {
    let parsed = value.parse::<i64>().map_err(|_| AppError::NotFound)?;
    if parsed <= 0 {
        return Err(AppError::NotFound);
    }
    Ok(parsed)
}

fn clean_optional(value: Option<String>) -> Option<String> {
    value.and_then(|value| clean_text(&value, MAX_BOOT_SERIAL_LEN))
}

fn user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| clean_text(value, MAX_BOOT_USER_AGENT_LEN))
}

fn remote_ip(connect: Option<SocketAddr>, headers: &HeaderMap) -> Option<String> {
    let peer_is_loopback = connect.map(|addr| addr.ip().is_loopback()).unwrap_or(false);
    if peer_is_loopback {
        if let Some(forwarded) = headers
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok())
            .and_then(last_valid_forwarded_ip)
        {
            return Some(forwarded);
        }
    }

    connect.map(|addr| addr.ip().to_string())
}

fn is_local_checker_request(
    query: &BootQuery,
    headers: &HeaderMap,
    connect: Option<SocketAddr>,
) -> bool {
    if !matches!(query.cybex_check.as_deref(), Some("1")) {
        return false;
    }
    if !connect.map(|addr| addr.ip().is_loopback()).unwrap_or(false) {
        return false;
    }
    headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(last_valid_forwarded_ip)
        .and_then(|ip| ip.parse::<IpAddr>().ok())
        .map(|ip| ip.is_loopback())
        .unwrap_or(true)
}

fn last_valid_forwarded_ip(value: &str) -> Option<String> {
    value
        .split(',')
        .rev()
        .find_map(|part| part.trim().parse::<IpAddr>().ok().map(|ip| ip.to_string()))
}

fn clean_text(value: &str, max_chars: usize) -> Option<String> {
    let cleaned = value
        .chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect::<String>();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.chars().take(max_chars).collect())
    }
}

fn ipxe_response(script: String) -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store, max-age=0"),
            (header::PRAGMA, "no-cache"),
            (header::EXPIRES, "0"),
        ],
        script,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use axum::http::{HeaderMap, HeaderValue, header};

    use super::{
        BootQuery, boot_profile_id_from_path, clean_optional, ipxe_response,
        is_local_checker_request, remote_ip, user_agent,
    };

    #[test]
    fn ipxe_responses_are_not_cached() {
        let response = ipxe_response("#!ipxe\n".to_string());

        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/plain; charset=utf-8"
        );
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store, max-age=0"
        );
        assert_eq!(response.headers().get(header::PRAGMA).unwrap(), "no-cache");
        assert_eq!(response.headers().get(header::EXPIRES).unwrap(), "0");
    }

    #[test]
    fn boot_request_serial_is_bounded_and_control_characters_are_removed() {
        let serial = format!(" serial\n{} ", "x".repeat(200));

        let cleaned = clean_optional(Some(serial)).unwrap();

        assert_eq!(cleaned.chars().count(), 128);
        assert!(!cleaned.contains('\n'));
        assert!(cleaned.starts_with("serial "));
    }

    #[test]
    fn boot_request_user_agent_is_bounded() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::USER_AGENT,
            HeaderValue::from_str(&format!("ipxe/1.0 {}", "x".repeat(400))).unwrap(),
        );

        let value = user_agent(&headers).unwrap();

        assert_eq!(value.chars().count(), 256);
        assert!(value.starts_with("ipxe/1.0 "));
    }

    #[test]
    fn boot_select_profile_id_rejects_invalid_values_as_not_found() {
        assert_eq!(boot_profile_id_from_path("42").unwrap(), 42);
        assert!(boot_profile_id_from_path("0").is_err());
        assert!(boot_profile_id_from_path("-1").is_err());
        assert!(boot_profile_id_from_path("not-a-number").is_err());
        assert!(boot_profile_id_from_path("999999999999999999999999999999").is_err());
    }

    #[test]
    fn forwarded_ip_is_trusted_only_from_loopback_proxy() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.10, 198.51.100.20"),
        );
        let loopback: SocketAddr = "127.0.0.1:50200".parse().unwrap();
        let remote: SocketAddr = "192.0.2.55:50200".parse().unwrap();

        assert_eq!(
            remote_ip(Some(loopback), &headers).as_deref(),
            Some("198.51.100.20")
        );
        assert_eq!(
            remote_ip(Some(remote), &headers).as_deref(),
            Some("192.0.2.55")
        );
    }

    #[test]
    fn forwarded_ip_ignores_invalid_values() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("spoofed, 2001:db8::12"),
        );
        let loopback: SocketAddr = "127.0.0.1:50200".parse().unwrap();

        assert_eq!(
            remote_ip(Some(loopback), &headers).as_deref(),
            Some("2001:db8::12")
        );
    }

    #[test]
    fn checker_marker_requires_loopback_request() {
        let query = BootQuery {
            mac: None,
            serial: None,
            cybex_check: Some("1".to_string()),
        };
        let mut headers = HeaderMap::new();
        let loopback: SocketAddr = "127.0.0.1:50200".parse().unwrap();
        let remote: SocketAddr = "192.0.2.55:50200".parse().unwrap();

        assert!(is_local_checker_request(&query, &headers, Some(loopback)));
        assert!(!is_local_checker_request(&query, &headers, Some(remote)));

        headers.insert("x-forwarded-for", HeaderValue::from_static("198.51.100.20"));
        assert!(!is_local_checker_request(&query, &headers, Some(loopback)));

        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("198.51.100.20, 127.0.0.1"),
        );
        assert!(is_local_checker_request(&query, &headers, Some(loopback)));
    }

    #[test]
    fn checker_marker_requires_exact_value() {
        let query = BootQuery {
            mac: None,
            serial: None,
            cybex_check: Some("true".to_string()),
        };
        let headers = HeaderMap::new();
        let loopback: SocketAddr = "127.0.0.1:50200".parse().unwrap();

        assert!(!is_local_checker_request(&query, &headers, Some(loopback)));
    }
}
