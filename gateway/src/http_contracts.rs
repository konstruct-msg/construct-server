use super::{GatewayState, SERVER_TRUST_REFRESH, ServerTrustCache, gateway_router};
use axum::{
    Router,
    body::{Body, Bytes, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use serde_json::{Value, json};
use std::{path::Path, time::Instant};
use tokio::sync::RwLock;
use tower::ServiceExt;

const DISCOVERY_PATHS: [&str; 2] = ["/.well-known/construct-server", "/.well-known/konstruct"];

fn state(trust_dir: &Path) -> GatewayState {
    GatewayState {
        instance_domain: "instance.example.test".into(),
        veil_relay_addresses: vec![],
        bundle_verification_key: None,
        token_encryption_key: None,
        federation_public_key: None,
        token_issuer_public: None,
        token_issuer_key_version: 7,
        server_trust: ServerTrustCache {
            dir: trust_dir.to_path_buf(),
            cached: RwLock::new(None),
        },
    }
}

async fn get(app: &Router, path: &str) -> Response {
    app.clone()
        .oneshot(Request::get(path).body(Body::empty()).expect("request"))
        .await
        .expect("router is infallible")
}

async fn body(response: Response) -> Bytes {
    to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("complete HTTP body")
}

async fn discovery(app: &Router, path: &str) -> Value {
    let response = get(app, path).await;
    assert_eq!(response.status(), StatusCode::OK, "{path}");
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "application/json",
        "{path}"
    );
    assert_eq!(
        response.headers()[header::CACHE_CONTROL],
        "public, max-age=3600",
        "{path}"
    );
    serde_json::from_slice(&body(response).await).expect("discovery JSON")
}

#[tokio::test]
async fn health_routes_answer_with_ok_not_just_a_success_status() {
    let dir = tempfile::tempdir().expect("isolated trust directory");
    let app = gateway_router(state(dir.path()));
    for path in ["/health", "/health/ready", "/health/live"] {
        let response = get(&app, path).await;
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "text/plain; charset=utf-8",
            "{path}"
        );
        assert_eq!(body(response).await.as_ref(), b"ok", "{path}");
    }
}

#[tokio::test]
async fn discovery_aliases_work_without_optional_keys_or_delegations() {
    let dir = tempfile::tempdir().expect("isolated empty trust directory");
    let app = gateway_router(state(dir.path()));
    let primary = discovery(&app, DISCOVERY_PATHS[0]).await;
    assert_eq!(discovery(&app, DISCOVERY_PATHS[1]).await, primary);
    assert_eq!(primary["version"], "1.0"); // Schema version, not build version.
    assert_eq!(primary["protocol"], "grpc");
    assert_eq!(
        primary["server"],
        json!({"domain": "instance.example.test"})
    );
    assert_eq!(primary["grpc_endpoint"], "instance.example.test:443");
    assert_eq!(primary["signaling_endpoint"], "instance.example.test:443");
    assert_eq!(primary["capabilities"]["supports_streaming"], true);
    let document = primary.as_object().expect("discovery document object");
    for key in [
        "server_trust",
        "bundle_verification_key",
        "token_encryption_key",
        "public_key",
        "federation",
        "commit",
        "build",
    ] {
        assert!(!document.contains_key(key), "unexpected {key}: {primary}");
    }
}

#[tokio::test]
async fn discovery_serves_configured_public_keys_and_nonempty_cached_delegations() {
    let dir = tempfile::tempdir().expect("isolated trust directory");
    let mut fixture = state(dir.path());
    fixture.bundle_verification_key = Some("bundle-fixture".into());
    fixture.token_encryption_key = Some("token-enc-fixture".into());
    fixture.federation_public_key = Some("federation-fixture".into());
    fixture.token_issuer_public = Some("issuer-fixture".into());
    // Test what's served, not signature validation or how the files are loaded.
    *fixture.server_trust.cached.get_mut() =
        Some((Instant::now(), vec!["delegation-fixture".into()]));
    let app = gateway_router(fixture);
    let primary = discovery(&app, DISCOVERY_PATHS[0]).await;
    assert_eq!(discovery(&app, DISCOVERY_PATHS[1]).await, primary);
    assert_eq!(primary["bundle_verification_key"], "bundle-fixture");
    assert_eq!(primary["token_encryption_key"], "token-enc-fixture");
    assert_eq!(primary["public_key"], "federation-fixture");
    assert_eq!(
        primary["server"],
        json!({
            "domain": "instance.example.test",
            "token_encryption_key": "token-enc-fixture",
            "token_issuer_public": "issuer-fixture",
            "token_issuer_key_version": 7,
        })
    );
    assert_eq!(
        primary["server_trust"],
        json!({"delegations": ["delegation-fixture"]})
    );
    assert_eq!(
        primary["federation"],
        json!({
            "enabled": true,
            "public_key": "federation-fixture",
            "protocol_version": "1.0",
            "endpoints": {"messages": "/federation/v1/messages", "sealed": "/federation/v1/sealed", "health": "/health"},
        })
    );
}

#[tokio::test]
async fn discovery_refreshes_stale_delegations_instead_of_readvertising_them() {
    let dir = tempfile::tempdir().expect("isolated empty trust directory");
    let mut fixture = state(dir.path());
    *fixture.server_trust.cached.get_mut() = Some((
        Instant::now() - 2 * SERVER_TRUST_REFRESH,
        vec!["stale-delegation-fixture".into()],
    ));
    let document = discovery(&gateway_router(fixture), DISCOVERY_PATHS[0]).await;
    assert!(
        !document
            .as_object()
            .expect("discovery document")
            .contains_key("server_trust")
    );
}

#[tokio::test]
async fn metrics_route_scrapes_the_registry_with_label_and_value() {
    let dir = tempfile::tempdir().expect("isolated trust directory");
    let app = gateway_router(state(dir.path()));
    // Seed the real registry the handler gathers. This proves exposition,
    // not that the gateway itself produces this particular counter.
    super::metrics::CALLS_INITIATED_TOTAL
        .with_label_values(&["gateway_http_fixture"])
        .inc_by(37);
    let response = get(&app, "/metrics").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "text/plain; version=0.0.4"
    );
    let bytes = body(response).await;
    let text = std::str::from_utf8(&bytes).expect("Prometheus text");
    assert!(
        text.lines()
            .any(|line| line == "# TYPE construct_calls_initiated_total counter")
    );
    assert!(
        text.lines().any(
            |line| line == r#"construct_calls_initiated_total{type="gateway_http_fixture"} 37"#
        )
    );
}
