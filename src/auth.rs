use axum::{
    body::Body,
    extract::{Form, State},
    http::{HeaderMap, Method, Request, StatusCode, header},
    middleware::Next,
    response::{Html, IntoResponse, Response},
};
use reqwest::Url;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::{AppState, assets::redirect_to, error::AppError, ui};

const ADMIN_SESSION_CONTEXT: &[u8] = b"cybex-boot-admin-session-v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AdminTokenSource {
    Bearer,
    Header,
    Cookie,
}

#[derive(Debug, Deserialize)]
pub struct LoginForm {
    pub token: String,
}

pub async fn require_admin(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    if let Some(source) = admin_token_source(&state, req.headers()) {
        if source == AdminTokenSource::Cookie
            && method_requires_origin(req.method())
            && !same_origin_admin_request(req.headers())
        {
            return AppError::Forbidden.into_response();
        }
        return next.run(req).await;
    }

    let wants_json = req.uri().path().starts_with("/api")
        || req
            .headers()
            .get(header::ACCEPT)
            .and_then(|value| value.to_str().ok())
            .map(|accept| accept.contains("application/json"))
            .unwrap_or(false);

    if wants_json {
        AppError::Unauthorized.into_response()
    } else {
        redirect_to("/login")
    }
}

pub async fn login_page() -> Html<String> {
    ui::render_login(None)
}

pub async fn login_submit(State(state): State<AppState>, Form(form): Form<LoginForm>) -> Response {
    if !constant_time_eq(form.token.trim(), &state.config.auth.admin_token) {
        return (
            StatusCode::UNAUTHORIZED,
            Html(ui::render_login(Some("Invalid token")).0),
        )
            .into_response();
    }

    let cookie = format!(
        "{}={}",
        state.config.auth.cookie_name,
        admin_session_cookie_attributes(&state.config.auth.admin_token, None)
    );

    (
        StatusCode::SEE_OTHER,
        [
            (header::LOCATION, "/".to_string()),
            (header::SET_COOKIE, cookie),
        ],
        Body::empty(),
    )
        .into_response()
}

pub async fn logout(State(state): State<AppState>) -> Response {
    let cookie = format!(
        "{}={}",
        state.config.auth.cookie_name,
        expired_session_cookie()
    );
    (
        StatusCode::SEE_OTHER,
        [
            (header::LOCATION, "/login".to_string()),
            (header::SET_COOKIE, cookie),
        ],
        Body::empty(),
    )
        .into_response()
}

pub fn token_is_valid(state: &AppState, headers: &HeaderMap) -> bool {
    admin_token_source(state, headers).is_some()
}

fn admin_token_source(state: &AppState, headers: &HeaderMap) -> Option<AdminTokenSource> {
    if let Some(token) = bearer_token(headers) {
        return constant_time_eq(&token, &state.config.auth.admin_token)
            .then_some(AdminTokenSource::Bearer);
    }
    if let Some(token) = headers
        .get("x-admin-token")
        .and_then(|value| value.to_str().ok())
    {
        return constant_time_eq(token.trim(), &state.config.auth.admin_token)
            .then_some(AdminTokenSource::Header);
    }
    if let Some(token) = cookie_token(headers, &state.config.auth.cookie_name) {
        return admin_session_cookie_is_valid(&token, &state.config.auth.admin_token)
            .then_some(AdminTokenSource::Cookie);
    }
    None
}

fn method_requires_origin(method: &Method) -> bool {
    !matches!(method, &Method::GET | &Method::HEAD | &Method::OPTIONS)
}

fn same_origin_admin_request(headers: &HeaderMap) -> bool {
    let Some(host) = request_host(headers) else {
        return false;
    };
    if let Some(origin) = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    {
        return header_url_host(origin).as_deref() == Some(host.as_str());
    }
    headers
        .get(header::REFERER)
        .and_then(|value| value.to_str().ok())
        .and_then(header_url_host)
        .as_deref()
        == Some(host.as_str())
}

fn request_host(headers: &HeaderMap) -> Option<String> {
    normalize_host(headers.get(header::HOST)?.to_str().ok()?)
}

fn header_url_host(value: &str) -> Option<String> {
    let parsed = Url::parse(value).ok()?;
    let host = parsed.host_str()?;
    let host = if let Some(port) = parsed.port() {
        format!("{host}:{port}")
    } else {
        host.to_string()
    };
    normalize_host(&host)
}

fn normalize_host(value: &str) -> Option<String> {
    let host = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty()
        || host
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        None
    } else {
        Some(host)
    }
}

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?.trim();
    value
        .strip_prefix("Bearer ")
        .map(|token| token.trim().to_string())
}

fn cookie_token(headers: &HeaderMap, cookie_name: &str) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for cookie in raw.split(';') {
        if let Some((name, value)) = cookie.trim().split_once('=') {
            if name == cookie_name {
                return urlencoding::decode(value)
                    .ok()
                    .map(|value| value.to_string());
            }
        }
    }
    None
}

fn admin_session_cookie_value(admin_token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(ADMIN_SESSION_CONTEXT);
    hasher.update(admin_token.as_bytes());
    format!("v1:{}", hex::encode(hasher.finalize()))
}

fn admin_session_cookie_attributes(admin_token: &str, max_age: Option<u64>) -> String {
    let mut cookie = format!(
        "{}; HttpOnly; SameSite=Strict; Path=/",
        urlencoding::encode(&admin_session_cookie_value(admin_token))
    );
    if let Some(max_age) = max_age {
        cookie.push_str(&format!("; Max-Age={max_age}"));
    }
    cookie
}

fn expired_session_cookie() -> String {
    "; HttpOnly; SameSite=Strict; Path=/; Max-Age=0".to_string()
}

fn admin_session_cookie_is_valid(cookie_value: &str, admin_token: &str) -> bool {
    constant_time_eq(cookie_value, &admin_session_cookie_value(admin_token))
}

fn constant_time_eq(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (left, right) in left.iter().zip(right.iter()) {
        diff |= left ^ right;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue, Method, header};

    use super::{
        admin_session_cookie_attributes, admin_session_cookie_is_valid, admin_session_cookie_value,
        constant_time_eq, method_requires_origin, same_origin_admin_request,
    };

    #[test]
    fn compares_tokens() {
        assert!(constant_time_eq("secret", "secret"));
        assert!(!constant_time_eq("secret", "secrex"));
        assert!(!constant_time_eq("secret", "secret-longer"));
    }

    #[test]
    fn admin_session_cookie_uses_derived_value() {
        let cookie = admin_session_cookie_value("secret");

        assert_ne!(cookie, "secret");
        assert_eq!(cookie.len(), 67);
        assert!(cookie.starts_with("v1:"));
        assert!(admin_session_cookie_is_valid(&cookie, "secret"));
        assert!(!admin_session_cookie_is_valid("secret", "secret"));
        assert!(!admin_session_cookie_is_valid(&cookie, "different-secret"));
    }

    #[test]
    fn admin_session_cookie_uses_strict_browser_attributes() {
        let cookie = admin_session_cookie_attributes("secret", None);

        assert!(cookie.starts_with("v1%3A"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Strict"));
        assert!(cookie.contains("Path=/"));
    }

    #[test]
    fn cookie_admin_mutations_require_origin() {
        assert!(!method_requires_origin(&Method::GET));
        assert!(method_requires_origin(&Method::POST));

        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("boot.example:8080"));
        assert!(!same_origin_admin_request(&headers));

        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("http://boot.example:8080"),
        );
        assert!(same_origin_admin_request(&headers));

        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("http://attacker.example"),
        );
        assert!(!same_origin_admin_request(&headers));
    }

    #[test]
    fn cookie_admin_origin_falls_back_to_referer() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("boot.example"));
        headers.insert(
            header::REFERER,
            HeaderValue::from_static("http://boot.example/devices"),
        );

        assert!(same_origin_admin_request(&headers));
    }
}
