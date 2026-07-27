// ============================================================================
// gRPC authentication helpers
// ============================================================================
//
// Production edge is vanilla Caddy reverse_proxy → h2c services (no JWT plugin,
// no header rewrite). Clients send on every authenticated RPC (see client docs):
//
//   Authorization: Bearer <access_token>
//   x-user-id:     <userId>      // advisory; MUST match token if present
//   x-device-id:   <deviceId>    // advisory; MUST match token if present
//
// Security rules:
//   1. Bearer access token is **required** for authenticated identity.
//   2. Identity is always `claims.sub` / `claims.device_id` — never a header alone.
//   3. If `x-user-id` / `x-device-id` is present, it must match the signed claims
//      (spoof detection). Legitimate clients that send both continue to work.
//
// Do NOT reintroduce "trust x-user-id without crypto verify" — that is an auth
// bypass on the public Caddy path.
// ============================================================================

use std::sync::Arc;

use tonic::{Status, metadata::MetadataMap};
use uuid::Uuid;

use construct_auth::{AuthManager, Claims};

/// Cryptographically verified caller identity from an access token.
#[derive(Debug, Clone)]
pub struct AuthedCaller {
    pub user_id: Uuid,
    pub device_id: Option<String>,
    pub jti: String,
    pub exp: i64,
}

/// Extract the Bearer access token from gRPC metadata.
///
/// Accepts both `authorization` and `Authorization` keys (HTTP/2 / tonic
/// metadata is case-insensitive for ASCII, but we check both for clarity).
pub fn extract_bearer_token(metadata: &MetadataMap) -> Result<&str, Status> {
    metadata
        .get("authorization")
        .or_else(|| metadata.get("Authorization"))
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .ok_or_else(|| Status::unauthenticated("Missing authentication"))
}

/// Verify the access token and enforce optional header consistency.
///
/// Returns verified [`Claims`]. Does **not** check the Redis revocation
/// blocklist — callers that need revocation (messaging) must do so separately
/// using `claims.jti`.
pub fn verify_access_token(
    auth_manager: &AuthManager,
    metadata: &MetadataMap,
) -> Result<Claims, Status> {
    let token = extract_bearer_token(metadata)?;
    let claims = auth_manager
        .verify_token(token)
        .map_err(|_| Status::unauthenticated("Invalid or expired token"))?;

    // Spoof guard: client-supplied x-user-id must match the signed subject.
    if let Some(header_uid) = metadata.get("x-user-id").and_then(|v| v.to_str().ok())
        && header_uid != claims.sub
    {
        tracing::warn!(
            header_user = %header_uid,
            token_sub = %claims.sub,
            "x-user-id does not match token subject — rejecting (possible spoof)"
        );
        return Err(Status::permission_denied(
            "x-user-id does not match authenticated user",
        ));
    }

    // Spoof guard: client-supplied x-device-id must match claims when claim is set.
    if let Some(header_did) = metadata.get("x-device-id").and_then(|v| v.to_str().ok())
        && let Some(claim_did) = claims.device_id.as_deref()
        && header_did != claim_did
    {
        tracing::warn!(
            header_device = %header_did,
            token_device = %claim_did,
            "x-device-id does not match token device_id — rejecting (possible spoof)"
        );
        return Err(Status::permission_denied(
            "x-device-id does not match authenticated device",
        ));
    }

    Ok(claims)
}

/// Parse verified claims into [`AuthedCaller`].
pub fn caller_from_claims(claims: &Claims) -> Result<AuthedCaller, Status> {
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| Status::unauthenticated("Invalid user ID in token claims"))?;
    Ok(AuthedCaller {
        user_id,
        device_id: claims.device_id.clone(),
        jti: claims.jti.clone(),
        exp: claims.exp,
    })
}

/// Full auth: verify token + header consistency → [`AuthedCaller`].
pub fn extract_authed_caller(
    auth_manager: &AuthManager,
    metadata: &MetadataMap,
) -> Result<AuthedCaller, Status> {
    let claims = verify_access_token(auth_manager, metadata)?;
    caller_from_claims(&claims)
}

/// Extract authenticated user UUID from gRPC request metadata.
///
/// Requires a valid Bearer access token. Optional `x-user-id` must match
/// `claims.sub` when present.
///
/// Returns `Status::unauthenticated` / `permission_denied` on failure.
pub fn extract_user_id(
    auth_manager: &Arc<AuthManager>,
    metadata: &MetadataMap,
) -> Result<Uuid, Status> {
    extract_authed_caller(auth_manager.as_ref(), metadata).map(|c| c.user_id)
}

/// Extract authenticated device_id.
///
/// Preference order after token verify:
/// 1. `claims.device_id` when present
/// 2. `x-device-id` header only for legacy tokens that lack a device claim
///    (still requires a valid Bearer user token)
pub fn extract_device_id(
    auth_manager: &AuthManager,
    metadata: &MetadataMap,
) -> Result<String, Status> {
    let caller = extract_authed_caller(auth_manager, metadata)?;
    if let Some(did) = caller.device_id {
        return Ok(did);
    }
    metadata
        .get("x-device-id")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .ok_or_else(|| Status::unauthenticated("Missing device identity"))
}

/// Extract both user_id and device_id (device required). Single token verify.
pub fn extract_user_and_device(
    auth_manager: &AuthManager,
    metadata: &MetadataMap,
) -> Result<(Uuid, String), Status> {
    let caller = extract_authed_caller(auth_manager, metadata)?;
    let device_id = match caller.device_id {
        Some(did) => did,
        None => metadata
            .get("x-device-id")
            .and_then(|v| v.to_str().ok())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .ok_or_else(|| Status::unauthenticated("Missing device identity"))?,
    };
    Ok((caller.user_id, device_id))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use construct_config::{
        ApnsConfig, ApnsEnvironment, CircuitBreakerConfig, Config, CsrfConfig, DbConfig,
        DeepLinksConfig, FederationConfig, LoggingConfig, MediaConfig, MicroservicesConfig,
        MtlsConfig, RedisChannels, RedisKeyPrefixes, SecurityConfig,
    };

    fn make_ed25519_keypair() -> (String, String) {
        use ed25519_compact::KeyPair;
        let kp = KeyPair::generate();
        (
            String::from_utf8(kp.sk.to_pem().as_bytes().to_vec()).expect("priv pem"),
            String::from_utf8(kp.pk.to_pem().as_bytes().to_vec()).expect("pub pem"),
        )
    }

    fn make_test_auth() -> AuthManager {
        let (priv_pem, pub_pem) = make_ed25519_keypair();
        let config = Config {
            database_url: String::new(),
            redis_url: String::new(),
            jwt_secret: "unused".to_string(),
            jwt_private_key: None,
            jwt_public_key: None,
            paseto_private_key: Some(priv_pem),
            paseto_public_key: Some(pub_pem),
            paseto_public_key_previous: Vec::new(),
            token_issue_format: "paseto".to_string(),
            port: 8080,
            bind_address: "127.0.0.1".to_string(),
            health_port: 8081,
            heartbeat_interval_secs: 60,
            server_registry_ttl_secs: 120,
            message_ttl_days: 7,
            dedup_safety_margin_hours: 2,
            access_token_ttl_hours: 24,
            session_ttl_days: 30,
            refresh_token_ttl_days: 7,
            jwt_issuer: "construct-test".to_string(),
            online_channel: "online".to_string(),
            offline_queue_prefix: "queue:".to_string(),
            delivery_queue_prefix: "delivery:".to_string(),
            delivery_poll_interval_ms: 100,
            grpc_keepalive_interval_secs: 45,
            grpc_keepalive_timeout_secs: 5,
            rust_log: "error".to_string(),
            logging: LoggingConfig {
                enable_message_metadata: false,
                enable_user_identifiers: false,
                hash_salt: "test-salt".to_string(),
            },
            security: SecurityConfig {
                prekey_ttl_days: 30,
                prekey_min_ttl_days: 7,
                prekey_max_ttl_days: 90,
                max_messages_per_hour: 1000,
                max_messages_per_ip_per_hour: 5000,
                max_key_rotations_per_day: 10,
                max_password_changes_per_day: 5,
                max_failed_login_attempts: 5,
                max_connections_per_user: 5,
                key_bundle_cache_hours: 1,
                rate_limit_block_duration_seconds: 3600,
                ip_rate_limiting_enabled: false,
                max_requests_per_ip_per_hour: 1000,
                combined_rate_limiting_enabled: false,
                max_requests_per_user_ip_per_hour: 500,
                max_long_poll_requests_per_window: 100,
                long_poll_rate_limit_window_secs: 60,
                request_signing_required: false,
                metrics_auth_enabled: false,
                metrics_ip_whitelist: vec![],
                metrics_bearer_token: None,
                max_pow_challenges_per_hour: 5,
                max_registrations_per_hour: 3,
                pow_difficulty: 1,
                username_hmac_secret: vec![0u8; 32],
                contact_hmac_secret: vec![0u8; 32],
                request_envelope_key: vec![0u8; 32],
            },
            apns: ApnsConfig {
                enabled: false,
                environment: ApnsEnvironment::Development,
                key_path: String::new(),
                key_id: String::new(),
                team_id: String::new(),
                bundle_id: String::new(),
                topic: String::new(),
                voip_topic: None,
                device_token_encryption_key: "0".repeat(64),
            },
            federation: FederationConfig {
                enabled: false,
                instance_domain: "test.local".to_string(),
                base_domain: "test.local".to_string(),
                signing_key_seed: None,
                max_requests_per_origin_per_hour: 1000,
                mtls: MtlsConfig {
                    required: false,
                    client_cert_path: None,
                    client_key_path: None,
                    verify_server_cert: false,
                    pinned_certs: std::collections::HashMap::new(),
                },
            },
            db: DbConfig {
                max_connections: 1,
                min_connections: 0,
                acquire_timeout_secs: 5,
                idle_timeout_secs: 60,
            },
            deeplinks: DeepLinksConfig {
                apple_team_id: String::new(),
                android_package_name: String::new(),
                android_cert_fingerprint: String::new(),
            },
            redis_key_prefixes: RedisKeyPrefixes {
                processed_msg: "processed_msg:".to_string(),
                user: "user:".to_string(),
                session: "session:".to_string(),
                user_sessions: "user_sessions:".to_string(),
                msg_hash: "msg_hash:".to_string(),
                rate: "rate:".to_string(),
                blocked: "blocked:".to_string(),
                key_bundle: "key_bundle:".to_string(),
                connections: "connections:".to_string(),
            },
            redis_channels: RedisChannels {
                dead_letter_queue: "dlq".to_string(),
                delivery_message: "delivery_message:{}".to_string(),
                delivery_notification: "delivery_notification:{}".to_string(),
            },
            media: MediaConfig {
                enabled: false,
                base_url: String::new(),
                upload_token_secret: String::new(),
                max_file_size: 10 * 1024 * 1024,
                rate_limit_per_hour: 100,
            },
            csrf: CsrfConfig {
                enabled: false,
                secret: "test-csrf-secret-at-least-32-chars!!".to_string(),
                token_ttl_secs: 3600,
                allowed_origins: vec![],
                cookie_name: "csrf_token".to_string(),
                header_name: "X-CSRF-Token".to_string(),
            },
            messaging: construct_config::MessagingConfig::default(),
            microservices: MicroservicesConfig {
                enabled: false,
                auth_service_url: "http://localhost:8001".to_string(),
                messaging_service_url: "http://localhost:8002".to_string(),
                user_service_url: "http://localhost:8003".to_string(),
                notification_service_url: "http://localhost:8004".to_string(),
                discovery_mode: "static".to_string(),
                service_timeout_secs: 30,
                circuit_breaker: CircuitBreakerConfig {
                    failure_threshold: 5,
                    success_threshold: 2,
                    timeout_secs: 60,
                },
            },
            instance_domain: "test.local".to_string(),
            federation_base_domain: "test.local".to_string(),
            federation_enabled: false,
            deep_link_base_url: String::new(),
            veil_enabled: false,
            veil_port: 9443,
            veil_server_key: None,
            veil_iat_mode: 0,
            veil_upstream: "envoy:8080".to_string(),
            veil_tls_cert_path: None,
            veil_tls_key_path: None,
            veil_cover_upstream: None,
            veil_relay_addresses: vec![],
        };
        AuthManager::new(&config).expect("test AuthManager")
    }

    fn meta_with(pairs: &[(&'static str, String)]) -> MetadataMap {
        let mut m = MetadataMap::new();
        for (k, v) in pairs {
            m.insert(*k, v.parse().unwrap());
        }
        m
    }

    #[test]
    fn bearer_only_succeeds() {
        let auth = make_test_auth();
        let uid = Uuid::new_v4();
        let (token, _, _) = auth
            .create_token_for_device(&uid, Some("dev123"))
            .expect("token");
        let meta = meta_with(&[("authorization", format!("Bearer {token}"))]);
        let got = extract_user_id(&Arc::new(auth), &meta).expect("auth ok");
        assert_eq!(got, uid);
    }

    #[test]
    fn bearer_plus_matching_headers_succeeds() {
        let auth = make_test_auth();
        let uid = Uuid::new_v4();
        let device = "aabbccddeeff00112233445566778899";
        let (token, _, _) = auth
            .create_token_for_device(&uid, Some(device))
            .expect("token");
        let meta = meta_with(&[
            ("authorization", format!("Bearer {token}")),
            ("x-user-id", uid.to_string()),
            ("x-device-id", device.to_string()),
        ]);
        let caller = extract_authed_caller(&auth, &meta).expect("auth ok");
        assert_eq!(caller.user_id, uid);
        assert_eq!(caller.device_id.as_deref(), Some(device));
    }

    #[test]
    fn spoofed_x_user_id_rejected() {
        let auth = make_test_auth();
        let real = Uuid::new_v4();
        let spoof = Uuid::new_v4();
        let (token, _, _) = auth.create_token_for_device(&real, Some("dev")).unwrap();
        let meta = meta_with(&[
            ("authorization", format!("Bearer {token}")),
            ("x-user-id", spoof.to_string()),
        ]);
        let err = extract_user_id(&Arc::new(auth), &meta).expect_err("must reject spoof");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn header_only_without_bearer_rejected() {
        let auth = make_test_auth();
        let uid = Uuid::new_v4();
        let meta = meta_with(&[
            ("x-user-id", uid.to_string()),
            ("x-device-id", "dev".to_string()),
        ]);
        let err = extract_user_id(&Arc::new(auth), &meta).expect_err("header alone must fail");
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn spoofed_x_device_id_rejected() {
        let auth = make_test_auth();
        let uid = Uuid::new_v4();
        let (token, _, _) = auth
            .create_token_for_device(&uid, Some("real-device-id-32chars!!!!!!"))
            .unwrap();
        let meta = meta_with(&[
            ("authorization", format!("Bearer {token}")),
            ("x-user-id", uid.to_string()),
            ("x-device-id", "attacker-device-id-spoofed!!!!".to_string()),
        ]);
        let err = extract_authed_caller(&auth, &meta).expect_err("device spoof");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn invalid_token_rejected() {
        let auth = make_test_auth();
        let meta = meta_with(&[("authorization", "Bearer not-a-real-token".to_string())]);
        let err = extract_user_id(&Arc::new(auth), &meta).expect_err("bad token");
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[test]
    fn missing_auth_rejected() {
        let auth = make_test_auth();
        let meta = MetadataMap::new();
        let err = extract_user_id(&Arc::new(auth), &meta).expect_err("no auth");
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }
}
