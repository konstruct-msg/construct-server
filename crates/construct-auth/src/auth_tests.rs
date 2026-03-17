// ============================================================================
// construct-auth Unit Tests
// ============================================================================
//
// Tests for JWT RS256 token creation and verification.
//
// Uses a self-generated 2048-bit RSA key pair that exists ONLY for tests.
// These keys are NOT secret — they must never be used in any real deployment.
//
// Run: cargo test --package construct-auth
// ============================================================================

#[cfg(test)]
#[allow(clippy::module_inception)]
mod auth_tests {
    use crate::AuthManager;
    use construct_config::{
        ApnsConfig, ApnsEnvironment, CircuitBreakerConfig, Config, CsrfConfig, DbConfig,
        DeepLinksConfig, FederationConfig, KafkaConfig, LoggingConfig, MediaConfig,
        MicroservicesConfig, MtlsConfig, RedisChannels, RedisKeyPrefixes, SecurityConfig,
        WorkerConfig,
    };
    use uuid::Uuid;

    // ── Test RSA key pair (2048-bit, test-only, NOT secret) ──────────────────

    const TEST_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCld/OtfVZXpWCA
W7dvc+St8EieR6L71C8INGXv3gjE41L8XwuZZB/bJGw/NJKf8NU+5YywG0C75044
LAHZAuxpf5sUAzwvO5x9dNkDMmOOgxh+F3JizEpWHWdY1kQkBApZXjI5OnsEklca
tpUMKGA4hbG2v3wwZsYlDtnxV2SNLWP6xalg42yCeB5sQ2qutlEckBH1NsuqJxvh
lzX6NlMSgSfidZk5cI7xQAeXJFn/hkOpnniXmWqSqo+CF6mIxO+e/t5T++Akdggj
gAjYroHMUPxv4VcdM66/DxZSaShSZCxy141Jew995b2NYTBnrIoOI1u20J63kJbR
A5nHJp9dAgMBAAECggEASALrlDnDXVJ2LHZ93u3PfFlhqSyhBDrEGyx+noUBSPpr
r7SHfkKiUINJ7rnpA91SWNSaxTufEQeptW2FglWw4Hrt2ShNRXsKcFjtZuRDio6I
FrwKhm/E/DRAuVtKfWgavujtL5XBWux7Jv+F3ywlMAQTIuaz2/amThNoCw3PD1cZ
PkEsiyKLAocxA+fUzjnn/VkRSs54DbBt+2k6NHsYGMkVkyV5BRX45Q9mlqX/jZes
8ITDPIM5Yro+54VqxHCrUm1kfiEBfdKtRJ3W7bUx7oYiRBnhZIFjrGRvdhuCtgQl
0XuulnPvV/wTs/FrGKivCLfP/4K2sxVBfnS0GT0tewKBgQDimh5BHEvFgLXoU6E0
oDIB/FxqRTEAYeQck41Yo4SEDhlWEjB43Zw1+4odWqxMzXsxWkEQzTDOlmVUs04f
wVJksm+rFC3oVIfifXN808eW9qgjZXewM8J4CyKq21jsiM+GGjQfyKG2IylTdI7v
b68pdSVEZPWlV807nh27hPrJfwKBgQC673nMlh4lsGWQW/0R85VY9NSsToR1z1Ub
0m/eI9335MBMdIrm4ePwPX2xx1lUmKNEduMx2CVx91iZGpobq9D8qb83YeF5wBGX
Wr325GeJoowD636g09ATes5GuQWAELI/pAsJtd9nq99WT1Rdbg7R4XDwAgF6WPbk
2RgsA+5tIwKBgDZCq03yBZ7UdDqek/JzDaZ2FHcJ/HLX/fRtzKHV/exVJ/H5Rwwa
HMa8ZdUjmjCF36LwtrXcPHyrfLYsfV+TPjSImb7AhUGlxCgS3C2e1KMsixR2vpM9
wapXGEULYx64n+C/s42M0FQ51TJ7raJd/vaRa4wWFNAz1xwYf4wgiqDnAoGAGEDv
5ZpoiO1NECDPQd//tY32dfCuAPcIjNaNyx2ONBaK2KCaUQBn6Yig4UsDDRXMwRpH
ufTYTuQPq7Wm3wY41D9V3uKlNX21CpUsZncV8+aSEgQg5s70hUJ+tvBUhVwlNFqd
UAI33SSQkosyX/jilVqRo6Iu/OfECMcd+r/71E8CgYEAllYdtzfQzZDvMVAAVWFE
178JOg+XamDmVpEBNHpkf9uHd0ZOjeYDxGDIKanx3jW2wxuYnoOB6il2VLnnlopL
oUjuuJ1DsuTogl3fIDWSAENs73Xr+gRJLdEs/ws2LsU59maEJ9uFE2yBgAVjjJyY
B18NCAe2Z/xN2IHjy5TyM1U=
-----END PRIVATE KEY-----";

    const TEST_PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApXfzrX1WV6VggFu3b3Pk
rfBInkei+9QvCDRl794IxONS/F8LmWQf2yRsPzSSn/DVPuWMsBtAu+dOOCwB2QLs
aX+bFAM8LzucfXTZAzJjjoMYfhdyYsxKVh1nWNZEJAQKWV4yOTp7BJJXGraVDChg
OIWxtr98MGbGJQ7Z8VdkjS1j+sWpYONsgngebENqrrZRHJAR9TbLqicb4Zc1+jZT
EoEn4nWZOXCO8UAHlyRZ/4ZDqZ54l5lqkqqPghepiMTvnv7eU/vgJHYII4AI2K6B
zFD8b+FXHTOuvw8WUmkoUmQscteNSXsPfeW9jWEwZ6yKDiNbttCet5CW0QOZxyaf
XQIDAQAB
-----END PUBLIC KEY-----";

    // ── Config builder ────────────────────────────────────────────────────────

    fn make_config(
        private_key: Option<&str>,
        public_key: Option<&str>,
        issuer: &str,
        ttl_hours: i64,
    ) -> Config {
        Config {
            database_url: String::new(),
            redis_url: String::new(),
            jwt_secret: "test-secret-not-used-in-rs256".to_string(),
            jwt_private_key: private_key.map(|s| s.to_string()),
            jwt_public_key: public_key.map(|s| s.to_string()),
            port: 8080,
            bind_address: "127.0.0.1".to_string(),
            health_port: 8081,
            heartbeat_interval_secs: 60,
            server_registry_ttl_secs: 120,
            message_ttl_days: 7,
            dedup_safety_margin_hours: 2,
            access_token_ttl_hours: ttl_hours,
            session_ttl_days: 30,
            refresh_token_ttl_days: 7,
            jwt_issuer: issuer.to_string(),
            online_channel: "online".to_string(),
            offline_queue_prefix: "queue:".to_string(),
            delivery_queue_prefix: "delivery:".to_string(),
            delivery_poll_interval_ms: 100,
            rust_log: "info".to_string(),
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
            },
            kafka: KafkaConfig {
                enabled: false,
                brokers: String::new(),
                topic: String::new(),
                consumer_group: String::new(),
                ssl_enabled: false,
                sasl_mechanism: None,
                sasl_username: None,
                sasl_password: None,
                ssl_ca_location: None,
                producer_compression: "none".to_string(),
                producer_acks: "1".to_string(),
                producer_linger_ms: 0,
                producer_batch_size: 0,
                producer_max_in_flight: 0,
                producer_retries: 0,
                producer_request_timeout_ms: 0,
                producer_delivery_timeout_ms: 0,
                producer_enable_idempotence: false,
            },
            apns: ApnsConfig {
                enabled: false,
                environment: ApnsEnvironment::Development,
                key_path: String::new(),
                key_id: String::new(),
                team_id: String::new(),
                bundle_id: String::new(),
                topic: String::new(),
                device_token_encryption_key: "0".repeat(64),
            },
            federation: FederationConfig {
                enabled: false,
                instance_domain: "test.local".to_string(),
                base_domain: "test.local".to_string(),
                signing_key_seed: None,
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
                acquire_timeout_secs: 5,
                idle_timeout_secs: 60,
            },
            deeplinks: DeepLinksConfig {
                apple_team_id: String::new(),
                android_package_name: String::new(),
                android_cert_fingerprint: String::new(),
            },
            worker: WorkerConfig {
                shadow_read_enabled: false,
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
                delivered_direct: "delivered_direct:".to_string(),
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
            ice_enabled: false,
            ice_port: 9443,
            ice_server_key: None,
            ice_iat_mode: 0,
            ice_relay_addresses: vec![],
        }
    }

    /// Builds an AuthManager in full mode (sign + verify) for testing.
    fn make_auth_manager_full() -> AuthManager {
        let config = make_config(
            Some(TEST_PRIVATE_KEY),
            Some(TEST_PUBLIC_KEY),
            "construct-test",
            1,
        );
        AuthManager::new(&config).expect("AuthManager::new failed with valid test keys")
    }

    /// Builds an AuthManager in verify-only mode (no private key).
    fn make_auth_manager_verify_only() -> AuthManager {
        let config = make_config(None, Some(TEST_PUBLIC_KEY), "construct-test", 1);
        AuthManager::new(&config).expect("AuthManager::new failed in verify-only mode")
    }

    // ── create_token / verify_token ───────────────────────────────────────────

    #[test]
    fn test_create_and_verify_access_token_round_trip() {
        let auth = make_auth_manager_full();
        let user_id = Uuid::new_v4();

        let (token, jti, exp) = auth.create_token(&user_id).expect("create_token failed");

        assert!(!token.is_empty());
        assert!(!jti.is_empty());
        assert!(
            exp > chrono::Utc::now().timestamp(),
            "exp must be in the future"
        );

        let claims = auth.verify_token(&token).expect("verify_token failed");

        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.jti, jti);
        assert_eq!(claims.iss, "construct-test");
        assert_eq!(claims.exp, exp);
    }

    #[test]
    fn test_create_and_verify_refresh_token_round_trip() {
        let auth = make_auth_manager_full();
        let user_id = Uuid::new_v4();

        let (token, jti, exp) = auth
            .create_refresh_token(&user_id)
            .expect("create_refresh_token failed");

        // Refresh TTL is 7 days — must be further out than access token
        let min_exp = chrono::Utc::now().timestamp() + 6 * 24 * 3600;
        assert!(
            exp > min_exp,
            "refresh token exp must be ~7 days in the future"
        );

        let claims = auth
            .verify_token(&token)
            .expect("verify_token of refresh token failed");
        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.jti, jti);
    }

    #[test]
    fn test_each_token_has_unique_jti() {
        let auth = make_auth_manager_full();
        let user_id = Uuid::new_v4();

        let (_, jti1, _) = auth.create_token(&user_id).unwrap();
        let (_, jti2, _) = auth.create_token(&user_id).unwrap();

        assert_ne!(jti1, jti2, "each token must have a unique JTI");
    }

    #[test]
    fn test_verify_token_wrong_issuer_fails() {
        let auth_signer = make_auth_manager_full();
        let auth_wrong_issuer =
            AuthManager::new(&make_config(None, Some(TEST_PUBLIC_KEY), "wrong-issuer", 1)).unwrap();

        let user_id = Uuid::new_v4();
        let (token, _, _) = auth_signer.create_token(&user_id).unwrap();

        let result = auth_wrong_issuer.verify_token(&token);
        assert!(
            result.is_err(),
            "token signed by one issuer must not verify against a different issuer"
        );
    }

    #[test]
    fn test_verify_expired_token_fails() {
        // Create a token with exp set 5 minutes in the PAST using test keys directly.
        // Can't use AuthManager(ttl=0) because jsonwebtoken has 60s default leeway.
        use crate::Claims;
        use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};

        let past_exp = chrono::Utc::now().timestamp() - 300; // 5 minutes ago
        let claims = Claims {
            sub: Uuid::new_v4().to_string(),
            jti: Uuid::new_v4().to_string(),
            exp: past_exp,
            iat: past_exp - 3600,
            iss: "construct-test".to_string(),
        };

        let key = EncodingKey::from_rsa_pem(TEST_PRIVATE_KEY.as_bytes()).unwrap();
        let token = encode(&Header::new(Algorithm::RS256), &claims, &key).unwrap();

        let auth = make_auth_manager_full();
        let result = auth.verify_token(&token);
        assert!(
            result.is_err(),
            "token with exp 5 minutes in the past must not verify"
        );
    }

    #[test]
    fn test_verify_only_mode_cannot_create_tokens() {
        let auth = make_auth_manager_verify_only();
        let user_id = Uuid::new_v4();

        assert!(
            auth.create_token(&user_id).is_err(),
            "verify-only mode must not create tokens"
        );
        assert!(
            auth.create_refresh_token(&user_id).is_err(),
            "verify-only mode must not create refresh tokens"
        );
    }

    #[test]
    fn test_verify_only_mode_can_verify_valid_token() {
        let auth_full = make_auth_manager_full();
        let auth_verify_only = make_auth_manager_verify_only();

        let user_id = Uuid::new_v4();
        let (token, _, _) = auth_full.create_token(&user_id).unwrap();

        let claims = auth_verify_only
            .verify_token(&token)
            .expect("verify-only mode must accept valid token");
        assert_eq!(claims.sub, user_id.to_string());
    }

    #[test]
    fn test_new_without_public_key_fails() {
        let config = make_config(None, None, "construct-test", 1);
        let result = AuthManager::new(&config);
        assert!(
            result.is_err(),
            "AuthManager::new must fail when no public key is provided"
        );
    }

    #[test]
    fn test_verify_garbage_token_fails() {
        let auth = make_auth_manager_full();
        assert!(auth.verify_token("not.a.jwt").is_err());
    }

    #[test]
    fn test_verify_empty_token_fails() {
        let auth = make_auth_manager_full();
        assert!(auth.verify_token("").is_err());
    }

    // ── Claims structure ──────────────────────────────────────────────────────

    #[test]
    fn test_claims_sub_is_user_uuid_string() {
        let auth = make_auth_manager_full();
        let user_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();

        let (token, _, _) = auth.create_token(&user_id).unwrap();
        let claims = auth.verify_token(&token).unwrap();

        assert_eq!(
            claims.sub, "550e8400-e29b-41d4-a716-446655440000",
            "sub claim must be the UUID in hyphenated string form"
        );
    }

    #[test]
    fn test_claims_iat_is_recent() {
        let auth = make_auth_manager_full();
        let now = chrono::Utc::now().timestamp();
        let user_id = Uuid::new_v4();

        let (token, _, _) = auth.create_token(&user_id).unwrap();
        let claims = auth.verify_token(&token).unwrap();

        assert!(
            claims.iat >= now - 5 && claims.iat <= now + 5,
            "iat must be within 5 seconds of now"
        );
    }
}
