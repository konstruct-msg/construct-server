// ============================================================================
// REST Bearer authentication (Axum)
// ============================================================================
//
// Production Caddy does not inject x-user-id. Any Axum route that used
// `TrustedUser` (header-only) was an auth-bypass if the HTTP port was ever
// reachable. These helpers require a cryptographically verified access token.
//
// ============================================================================

use axum::http::HeaderMap;
use construct_auth::AuthManager;
use construct_error::AppError;
use uuid::Uuid;

/// Verify `Authorization: Bearer <access_token>` and return `claims.sub` as Uuid.
///
/// If `x-user-id` is present it must match the token subject (spoof guard).
/// Header-only identity is never accepted.
pub fn require_bearer_user_id(auth: &AuthManager, headers: &HeaderMap) -> Result<Uuid, AppError> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .ok_or_else(|| AppError::Auth("Missing authentication".into()))?;

    let claims = auth
        .verify_token(token)
        .map_err(|_| AppError::Auth("Invalid or expired token".into()))?;

    if let Some(header_uid) = headers.get("x-user-id").and_then(|v| v.to_str().ok())
        && header_uid != claims.sub
    {
        tracing::warn!(
            header_user = %header_uid,
            token_sub = %claims.sub,
            "REST x-user-id does not match token subject — rejecting"
        );
        return Err(AppError::Auth(
            "x-user-id does not match authenticated user".into(),
        ));
    }

    Uuid::parse_str(&claims.sub)
        .map_err(|_| AppError::Auth("Invalid user ID in token claims".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use construct_config::{
        ApnsConfig, ApnsEnvironment, CircuitBreakerConfig, Config, CsrfConfig, DbConfig,
        DeepLinksConfig, FederationConfig, LoggingConfig, MediaConfig, MicroservicesConfig,
        MtlsConfig, RedisChannels, RedisKeyPrefixes, SecurityConfig,
    };

    fn make_auth() -> AuthManager {
        let kp = ed25519_compact::KeyPair::generate();
        let priv_pem = String::from_utf8(kp.sk.to_pem().as_bytes().to_vec()).unwrap();
        let pub_pem = String::from_utf8(kp.pk.to_pem().as_bytes().to_vec()).unwrap();
        let config = Config {
            database_url: String::new(),
            redis_url: String::new(),
            jwt_secret: "unused".into(),
            jwt_private_key: None,
            jwt_public_key: None,
            paseto_private_key: Some(priv_pem),
            paseto_public_key: Some(pub_pem),
            paseto_public_key_previous: vec![],
            token_issue_format: "paseto".into(),
            port: 0,
            bind_address: "127.0.0.1".into(),
            health_port: 0,
            heartbeat_interval_secs: 60,
            server_registry_ttl_secs: 120,
            message_ttl_days: 7,
            dedup_safety_margin_hours: 2,
            access_token_ttl_hours: 24,
            session_ttl_days: 30,
            refresh_token_ttl_days: 7,
            jwt_issuer: "construct-test".into(),
            online_channel: "online".into(),
            offline_queue_prefix: "queue:".into(),
            delivery_queue_prefix: "delivery:".into(),
            delivery_poll_interval_ms: 100,
            grpc_keepalive_interval_secs: 45,
            grpc_keepalive_timeout_secs: 5,
            rust_log: "error".into(),
            logging: LoggingConfig {
                enable_message_metadata: false,
                enable_user_identifiers: false,
                hash_salt: "test".into(),
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
                instance_domain: "test.local".into(),
                base_domain: "test.local".into(),
                signing_key_seed: None,
                max_requests_per_origin_per_hour: 1000,
                mtls: MtlsConfig {
                    required: false,
                    client_cert_path: None,
                    client_key_path: None,
                    verify_server_cert: false,
                    pinned_certs: Default::default(),
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
                processed_msg: "processed_msg:".into(),
                user: "user:".into(),
                session: "session:".into(),
                user_sessions: "user_sessions:".into(),
                msg_hash: "msg_hash:".into(),
                rate: "rate:".into(),
                blocked: "blocked:".into(),
                key_bundle: "key_bundle:".into(),
                connections: "connections:".into(),
            },
            redis_channels: RedisChannels {
                dead_letter_queue: "dlq".into(),
                delivery_message: "delivery_message:{}".into(),
                delivery_notification: "delivery_notification:{}".into(),
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
                secret: "test-csrf-secret-at-least-32-chars!!".into(),
                token_ttl_secs: 3600,
                allowed_origins: vec![],
                cookie_name: "csrf_token".into(),
                header_name: "X-CSRF-Token".into(),
            },
            messaging: Default::default(),
            microservices: MicroservicesConfig {
                enabled: false,
                auth_service_url: "http://localhost:8001".into(),
                messaging_service_url: "http://localhost:8002".into(),
                user_service_url: "http://localhost:8003".into(),
                notification_service_url: "http://localhost:8004".into(),
                discovery_mode: "static".into(),
                service_timeout_secs: 30,
                circuit_breaker: CircuitBreakerConfig {
                    failure_threshold: 5,
                    success_threshold: 2,
                    timeout_secs: 60,
                },
            },
            instance_domain: "test.local".into(),
            federation_base_domain: "test.local".into(),
            federation_enabled: false,
            deep_link_base_url: String::new(),
            veil_enabled: false,
            veil_port: 9443,
            veil_server_key: None,
            veil_iat_mode: 0,
            veil_upstream: "envoy:8080".into(),
            veil_tls_cert_path: None,
            veil_tls_key_path: None,
            veil_cover_upstream: None,
            veil_relay_addresses: vec![],
        };
        AuthManager::new(&config).expect("test auth")
    }

    #[test]
    fn rejects_missing_and_header_only() {
        let auth = make_auth();
        let mut headers = HeaderMap::new();
        assert!(require_bearer_user_id(&auth, &headers).is_err());
        headers.insert("x-user-id", Uuid::new_v4().to_string().parse().unwrap());
        assert!(require_bearer_user_id(&auth, &headers).is_err());
    }

    #[test]
    fn accepts_valid_bearer() {
        let auth = make_auth();
        let uid = Uuid::new_v4();
        let (token, _, _) = auth.create_token_for_device(&uid, Some("dev")).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        assert_eq!(require_bearer_user_id(&auth, &headers).unwrap(), uid);
    }

    #[test]
    fn rejects_spoofed_x_user_id() {
        let auth = make_auth();
        let uid = Uuid::new_v4();
        let (token, _, _) = auth.create_token_for_device(&uid, Some("dev")).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        headers.insert("x-user-id", Uuid::new_v4().to_string().parse().unwrap());
        assert!(require_bearer_user_id(&auth, &headers).is_err());
    }
}
