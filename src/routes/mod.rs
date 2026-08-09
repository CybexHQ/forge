pub mod boot;
pub mod files;

use axum::{
    Router,
    body::Body,
    extract::DefaultBodyLimit,
    http::{HeaderMap, HeaderName, HeaderValue, Request, Uri, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
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

async fn healthz() -> Response {
    ([(header::CONTENT_TYPE, "text/plain")], "ok\n").into_response()
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
    use std::{fs, path::PathBuf};

    use axum::{
        body::{Body, to_bytes},
        http::{HeaderMap, Request, StatusCode},
    };
    use tower::ServiceExt;

    use crate::{AppState, config::AppConfig, db};

    use super::{
        CONTENT_SECURITY_POLICY, REQUEST_BODY_LIMIT_BYTES, apply_security_headers,
        request_trace_path, router,
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

        for (path, expected) in [
            (
                "/cache/nix-cache-info".to_string(),
                b"cache-info".as_slice(),
            ),
            (
                format!("/cache/{store_hash}.narinfo"),
                b"narinfo".as_slice(),
            ),
            (
                format!("/cache/nar/{file_hash}.nar.xz"),
                b"compressed-nar".as_slice(),
            ),
        ] {
            let response = app
                .clone()
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
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
        let root = temp_test_dir("cybex-pulse-router");
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
database_path = "{root}/data/cybex-pulse.sqlite"
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
        let path = std::env::temp_dir().join(format!(
            "{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        path
    }
}
