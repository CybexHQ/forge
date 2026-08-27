pub mod boot;
pub mod files;

use std::net::SocketAddr;

use axum::{
    Router,
    body::Body,
    extract::{ConnectInfo, DefaultBodyLimit, Query, State},
    http::{HeaderMap, HeaderName, HeaderValue, Request, StatusCode, Uri, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::Deserialize;
use tower_http::trace::TraceLayer;

use crate::{AppState, netboot};

const REQUEST_BODY_LIMIT_BYTES: usize = 1024;
const CONTENT_SECURITY_POLICY: &str = concat!(
    "default-src 'none'; ",
    "base-uri 'none'; ",
    "frame-ancestors 'none'; ",
    "form-action 'self'"
);

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/boot", get(boot::boot_root))
        .route("/boot.ipxe", get(boot::boot_root))
        .route("/boot/:mac", get(boot::boot_mac))
        .route("/boot/:mac/kexec.json", get(boot::boot_kexec))
        .route("/boot/by-serial/:serial", get(boot::boot_serial))
        .route("/boot/select/:profile_id", get(boot::boot_select_profile))
        .route("/files/*path", get(files::boot_file))
        .route("/cache/*path", get(files::cache_file))
        .route(
            "/netboot/:bundle_sha256/:component",
            get(netboot::serve_component),
        )
        .route(
            "/boot-session/:session_id/context.cpio",
            get(netboot::serve_context),
        )
        .layer(DefaultBodyLimit::max(REQUEST_BODY_LIMIT_BYTES))
        .layer(middleware::from_fn(add_security_headers))
        .layer(TraceLayer::new_for_http().make_span_with(request_trace_span))
        .with_state(state)
}

fn request_trace_span(request: &Request<Body>) -> tracing::Span {
    tracing::debug_span!(
        target: "tower_http::trace",
        "request",
        method = %request.method(),
        path = %request_trace_path(request.uri()),
        version = ?request.version(),
    )
}

fn request_trace_path(uri: &Uri) -> &str {
    if uri.path().starts_with("/boot-session/") {
        "/boot-session/:session_id/context.cpio"
    } else {
        uri.path()
    }
}

#[derive(Deserialize)]
struct HealthQuery {
    cybex_fresh: Option<String>,
}

async fn healthz(
    State(state): State<AppState>,
    Query(query): Query<HealthQuery>,
    headers: HeaderMap,
    connect: Option<ConnectInfo<SocketAddr>>,
) -> Response {
    let fresh = matches!(query.cybex_fresh.as_deref(), Some("1"))
        && is_direct_loopback_request(&headers, connect.map(|value| value.0));
    let readiness = if fresh {
        crate::readiness::probe_fresh(&state).await
    } else {
        crate::readiness::probe(&state).await
    };
    if readiness.ready {
        ([(header::CONTENT_TYPE, "text/plain")], "ok\n").into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            [(header::CONTENT_TYPE, "text/plain")],
            "not ready\n",
        )
            .into_response()
    }
}

fn is_direct_loopback_request(headers: &HeaderMap, connect: Option<SocketAddr>) -> bool {
    connect
        .map(|address| address.ip().is_loopback())
        .unwrap_or(false)
        && !headers.contains_key("forwarded")
        && !headers.contains_key("x-forwarded-for")
}

async fn add_security_headers(req: Request<Body>, next: Next) -> Response {
    let mut response = next.run(req).await;
    apply_security_headers(response.headers_mut());
    response
}

fn apply_security_headers(headers: &mut HeaderMap) {
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static(CONTENT_SECURITY_POLICY),
    );
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        net::SocketAddr,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use axum::{
        body::{Body, to_bytes},
        extract::ConnectInfo,
        http::{HeaderMap, HeaderValue, Request, StatusCode},
    };
    use tower::ServiceExt;

    use crate::models::{BootProfileType, CreateBootProfileRequest, CreateDeviceRequest};
    use crate::{AppState, config::AppConfig, db};

    use super::{
        CONTENT_SECURITY_POLICY, REQUEST_BODY_LIMIT_BYTES, apply_security_headers,
        is_direct_loopback_request, request_trace_path, router,
    };

    #[test]
    fn request_body_limit_is_explicit_and_bounded() {
        assert_eq!(REQUEST_BODY_LIMIT_BYTES, 1024);
    }

    #[test]
    fn security_headers_are_applied() {
        let mut headers = HeaderMap::new();

        apply_security_headers(&mut headers);

        assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
        assert_eq!(headers.get("x-frame-options").unwrap(), "DENY");
        assert_eq!(headers.get("referrer-policy").unwrap(), "no-referrer");
        assert_eq!(
            headers.get("content-security-policy").unwrap(),
            CONTENT_SECURITY_POLICY
        );
        assert!(headers.get("cache-control").is_none());
    }

    #[test]
    fn request_trace_path_omits_query_string() {
        let uri = "/boot.ipxe?mac=aa:bb:cc:dd:ee:ff&serial=sensitive"
            .parse()
            .unwrap();

        assert_eq!(request_trace_path(&uri), "/boot.ipxe");
    }

    #[test]
    fn uncached_health_probe_is_available_only_directly_from_loopback() {
        let direct: SocketAddr = "127.0.0.1:50200".parse().unwrap();
        let remote: SocketAddr = "192.0.2.55:50200".parse().unwrap();
        let mut headers = HeaderMap::new();

        assert!(is_direct_loopback_request(&headers, Some(direct)));
        assert!(!is_direct_loopback_request(&headers, Some(remote)));
        assert!(!is_direct_loopback_request(&headers, None));

        headers.insert("x-forwarded-for", HeaderValue::from_static("127.0.0.1"));
        assert!(!is_direct_loopback_request(&headers, Some(direct)));
        headers.remove("x-forwarded-for");
        headers.insert("forwarded", HeaderValue::from_static("for=127.0.0.1"));
        assert!(!is_direct_loopback_request(&headers, Some(direct)));
    }

    #[tokio::test]
    async fn managed_only_router_drops_local_management_but_keeps_boot_routes() {
        let state = test_state().await;
        let app = router(state);

        let login = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/login")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(login.status(), StatusCode::NOT_FOUND);

        let api = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/devices")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(api.status(), StatusCode::NOT_FOUND);

        let health = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(health.status(), StatusCode::OK);

        let boot = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/boot.ipxe?cybex_check=1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(boot.status(), StatusCode::OK);
        let boot_body = to_bytes(boot.into_body(), 64 * 1024).await.unwrap();
        assert!(boot_body.starts_with(b"#!ipxe"));

        let file = app
            .oneshot(
                Request::builder()
                    .uri("/files/probe.txt")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(file.status(), StatusCode::OK);
        let file_body = to_bytes(file.into_body(), 1024).await.unwrap();
        assert_eq!(&file_body[..], b"probe\n");
    }

    #[tokio::test]
    async fn trusted_loopback_self_probe_does_not_record_a_boot_event() {
        let state = test_state().await;
        let app = router(state.clone());
        let mut request = Request::builder()
            .uri("/boot.ipxe?cybex_check=1")
            .header("x-forwarded-for", "127.0.0.1")
            .body(Body::empty())
            .unwrap();
        request.extensions_mut().insert(ConnectInfo(
            "127.0.0.1:50200".parse::<SocketAddr>().unwrap(),
        ));

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            db::list_boot_events(&state.db, 10)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn failed_automatic_enrollment_keeps_the_mac_fresh_for_a_safe_retry() {
        let state = test_state().await;
        db::create_profile(
            &state.db,
            CreateBootProfileRequest {
                name: "Default Enrollment".to_string(),
                description: None,
                profile_type: BootProfileType::JamesInstaller,
                enabled: Some(true),
                is_default: Some(true),
                one_time: Some(false),
                raw_script: None,
            },
        )
        .await
        .unwrap();
        let app = router(state.clone());

        // The test state intentionally has no verified installer bundle. The
        // request therefore fails closed after choosing enrollment. Its
        // discovery-only row must be rolled back so a later retry can recover
        // automatically once the runtime becomes ready.
        let first = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/boot/aa-bb-cc-dd-ee-ff")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(
            db::get_device_by_mac(&state.db, "aa:bb:cc:dd:ee:ff")
                .await
                .unwrap()
                .is_none()
        );

        let retry = app
            .oneshot(
                Request::builder()
                    .uri("/boot/aa-bb-cc-dd-ee-ff")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(retry.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(
            db::get_device_by_mac(&state.db, "aa:bb:cc:dd:ee:ff")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn known_unassigned_mac_probes_local_disk_and_retains_the_menu_fallback() {
        let state = test_state().await;
        db::create_profile(
            &state.db,
            CreateBootProfileRequest {
                name: "Default Enrollment".to_string(),
                description: None,
                profile_type: BootProfileType::JamesInstaller,
                enabled: Some(true),
                is_default: Some(true),
                one_time: Some(false),
                raw_script: None,
            },
        )
        .await
        .unwrap();
        db::create_device(
            &state.db,
            CreateDeviceRequest {
                mac: "aa:bb:cc:dd:ee:ff".to_string(),
                hostname: None,
                serial_number: None,
                notes: None,
                tags: None,
                default_profile_id: None,
                one_time_profile_id: None,
            },
        )
        .await
        .unwrap();
        let app = router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/boot/aa-bb-cc-dd-ee-ff")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = String::from_utf8(
            to_bytes(response.into_body(), 64 * 1024)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(body.contains(
            ":known_local_efi\nsanboot --no-describe --drive 0x80 || goto known_local_efi_handoff\ngoto end\n:known_local_efi_handoff\necho Returning control to UEFI for the next boot entry\nset cybex-local-handoff 1\nexit 1"
        ));
        assert!(!body.contains("sanboot --drive 0"));
        assert!(body.contains("item profile_"));
        assert!(body.contains("Default Enrollment"));
    }

    #[tokio::test]
    async fn cache_route_serves_only_static_binary_cache_members() {
        let state = test_state().await;
        let cache_root = state.config.cache.root_dir.clone();
        let store_hash = "0".repeat(32);
        let file_hash = "1".repeat(52);
        fs::create_dir_all(cache_root.join("nar")).unwrap();
        fs::write(cache_root.join("nix-cache-info"), b"cache-info").unwrap();
        fs::write(cache_root.join(format!("{store_hash}.narinfo")), b"narinfo").unwrap();
        fs::write(
            cache_root.join(format!("nar/{file_hash}.nar.xz")),
            b"compressed-nar",
        )
        .unwrap();
        fs::write(cache_root.join("cache-priv-key.pem"), b"private-key").unwrap();
        let app = router(state);

        for (path, expected, cache_control) in [
            (
                "/cache/nix-cache-info".to_string(),
                b"cache-info".as_slice(),
                "public, max-age=60",
            ),
            (
                format!("/cache/{store_hash}.narinfo"),
                b"narinfo".as_slice(),
                "public, max-age=60",
            ),
            (
                format!("/cache/nar/{file_hash}.nar.xz"),
                b"compressed-nar".as_slice(),
                "public, max-age=31536000, immutable",
            ),
        ] {
            let response = app
                .clone()
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response.headers().get("cache-control").unwrap(),
                cache_control
            );
            assert_eq!(
                &to_bytes(response.into_body(), 1024).await.unwrap()[..],
                expected
            );
        }

        for path in [
            "/cache/cache-priv-key.pem",
            "/cache/manifest.json",
            "/cache/nar/not-a-cache-member.txt",
        ] {
            let response = app
                .clone()
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
        }
    }

    async fn test_state() -> AppState {
        let root = temp_test_dir("cybex-james-router");
        let config_path = root.join("config.toml");
        let www = root.join("www");
        fs::create_dir_all(&www).unwrap();
        fs::write(www.join("probe.txt"), "probe\n").unwrap();
        fs::write(
            &config_path,
            format!(
                r#"
[server]
listen_addr = "127.0.0.1:8080"
public_base_url = "http://boot.example"

[paths]
data_dir = "{root}/data"
database_path = "{root}/data/cybex-james.sqlite"
boot_assets_dir = "{root}/www"
static_dir = "{root}/www/assets"
tftp_dir = "{root}/tftp"

[build]
work_dir = "{root}/build/work"
output_dir = "{root}/build/outputs"

[cache]
root_dir = "{root}/www/cache"
private_key_path = "{root}/cache/cache-priv-key.pem"
public_key_path = "{root}/cache/cache-pub-key.pem"

[manage]
state_path = "{root}/manage-state.json"
"#,
                root = root.display()
            ),
        )
        .unwrap();
        let config = AppConfig::load(&config_path).unwrap();
        db::ensure_directories(&config).unwrap();
        let pool = db::connect(&config).await.unwrap();
        db::migrate(&pool).await.unwrap();
        AppState::new(config, pool)
    }

    fn temp_test_dir(label: &str) -> PathBuf {
        static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        for _ in 0..100 {
            let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("{label}-{}-{unique}-{id}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return path,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("create router test directory {}: {error}", path.display()),
            }
        }
        panic!("failed to allocate a unique router test directory")
    }
}
