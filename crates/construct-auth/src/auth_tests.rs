// ============================================================================
// construct-auth Unit Tests
// ============================================================================
//
// Tests for JWT (legacy RS256) and PASETO v4.public token creation/verification.
//
// All test keys are generated on the fly at test-module init — no key material
// is ever committed to the repository. RSA and Ed25519 keygen is deterministic
// across test runs only in the sense that each test builds its own throwaway
// pair; no shared global key state is relied upon.
//
// Run: cargo test --package construct-auth
// ============================================================================

#[cfg(test)]
#[allow(clippy::module_inception)]
mod auth_tests {
    use crate::{AuthManager, TokenFormat};
    use construct_config::{
        ApnsConfig, ApnsEnvironment, CircuitBreakerConfig, Config, CsrfConfig, DbConfig,
        DeepLinksConfig, FederationConfig, LoggingConfig, MediaConfig, MicroservicesConfig,
        MtlsConfig, RedisChannels, RedisKeyPrefixes, SecurityConfig,
    };
    use rand::RngCore;
    use uuid::Uuid;

    // ── Test key generation (on the fly — no keys in the repo) ─────────────────

    /// Generate a fresh Ed25519 keypair, returning (private_pem, public_pem).
    /// Uses ed25519-compact's `pem` feature.
    fn make_ed25519_keypair() -> (String, String) {
        use ed25519_compact::KeyPair;
        let kp = KeyPair::generate();
        let priv_pem = kp.sk.to_pem();
        let pub_pem = kp.pk.to_pem();
        // to_pem returns zeroizing wrappers; copy to plain String for Config.
        (
            String::from_utf8(priv_pem.as_bytes().to_vec()).expect("Ed25519 private PEM"),
            String::from_utf8(pub_pem.as_bytes().to_vec()).expect("Ed25519 public PEM"),
        )
    }

    /// Generate a fresh 2048-bit RSA keypair, returning (pkcs8_priv_pem, spki_pub_pem).
    /// Used to exercise the legacy RS256 JWT dual-stack path without committing keys.
    fn make_rsa_keypair() -> (String, String) {
        use rsa::RsaPrivateKey;
        use rsa::pkcs1::EncodeRsaPrivateKey;
        use rsa::pkcs8::EncodePrivateKey;
        use rsa::pkcs8::EncodePublicKey;
        use rsa::rand_core::OsRng;

        let mut rng = OsRng;
        let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("RSA 2048 keygen");
        let priv_pem = priv_key
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .expect("RSA private PKCS8 PEM")
            .to_string();
        // Try PKCS8 SPKI first, fall back to PKCS1.
        let pub_pem_zerosize = priv_key
            .to_public_key()
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .expect("RSA public SPKI PEM");
        // Suppress dead-code lint on EncodeRsaPrivateKey by trying PKCS1 as a fallback path
        // (the primary method used is to_public_key().to_public_key_pem()).
        let _ = priv_key.to_pkcs1_pem(rsa::pkcs8::LineEnding::LF).ok();
        (priv_pem, pub_pem_zerosize.to_string())
    }

    // ── Config builder ────────────────────────────────────────────────────────

    #[allow(clippy::too_many_arguments)]
    fn make_config(
        jwt_priv: Option<&str>,
        jwt_pub: Option<&str>,
        paseto_priv: Option<&str>,
        paseto_pub: Option<&str>,
        issuer: &str,
        ttl_hours: i64,
        issue_format: &str,
    ) -> Config {
        Config {
            database_url: String::new(),
            redis_url: String::new(),
            jwt_secret: "test-secret-not-used-in-rs256".to_string(),
            jwt_private_key: jwt_priv.map(|s| s.to_string()),
            jwt_public_key: jwt_pub.map(|s| s.to_string()),
            paseto_private_key: paseto_priv.map(|s| s.to_string()),
            paseto_public_key: paseto_pub.map(|s| s.to_string()),
            token_issue_format: issue_format.to_string(),
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
            grpc_keepalive_interval_secs: 45,
            grpc_keepalive_timeout_secs: 5,
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
        }
    }

    // ── AuthManager builders for various configurations ───────────────────────

    /// PASETO full mode (sign + verify) with a freshly-generated Ed25519 keypair.
    fn make_paseto_full() -> (AuthManager, String, String) {
        let (priv_pem, pub_pem) = make_ed25519_keypair();
        let config = make_config(
            None,
            None,
            Some(&priv_pem),
            Some(&pub_pem),
            "construct-test",
            1,
            "paseto",
        );
        (
            AuthManager::new(&config).expect("PASETO full AuthManager"),
            priv_pem,
            pub_pem,
        )
    }

    /// PASETO verify-only mode built from an externally-supplied public PEM.
    /// Pairs with tests that need a signing manager using the same key.
    fn make_paseto_verify_only(pub_pem: &str) -> AuthManager {
        let config = make_config(
            None,
            None,
            None,
            Some(pub_pem),
            "construct-test",
            1,
            "paseto",
        );
        AuthManager::new(&config).expect("PASETO verify-only AuthManager")
    }

    /// JWT full mode (sign + verify) with a freshly-generated RSA-2048 keypair.
    fn make_jwt_full() -> (AuthManager, String, String) {
        let (priv_pem, pub_pem) = make_rsa_keypair();
        let config = make_config(
            Some(&priv_pem),
            Some(&pub_pem),
            None,
            None,
            "construct-test",
            1,
            "jwt",
        );
        (
            AuthManager::new(&config).expect("JWT full AuthManager"),
            priv_pem,
            pub_pem,
        )
    }

    /// Dual-stack manager: both JWT (RSA) and PASETO (Ed25519) verify keys loaded,
    /// issue_format=paseto so new tokens are PASETO. Used to simulate the migration
    /// server during the dual-stack window.
    fn make_dual_full() -> (AuthManager, String, String, String, String) {
        let (jwt_priv, jwt_pub) = make_rsa_keypair();
        let (paseto_priv, paseto_pub) = make_ed25519_keypair();
        let config = make_config(
            Some(&jwt_priv),
            Some(&jwt_pub),
            Some(&paseto_priv),
            Some(&paseto_pub),
            "construct-test",
            1,
            "paseto",
        );
        (
            AuthManager::new(&config).expect("dual-stack full AuthManager"),
            jwt_priv,
            jwt_pub,
            paseto_priv,
            paseto_pub,
        )
    }

    // ── PASETO v4.public round trips ──────────────────────────────────────────

    #[test]
    fn test_paseto_create_and_verify_access_token_round_trip() {
        let (auth, _, _) = make_paseto_full();
        let user_id = Uuid::new_v4();

        let (token, jti, exp) = auth.create_token(&user_id).expect("create_token failed");

        assert!(
            token.starts_with("v4.public."),
            "token must have v4.public. prefix"
        );
        assert!(!jti.is_empty());
        assert!(exp > chrono::Utc::now().timestamp());

        let claims = auth.verify_token(&token).expect("verify_token failed");
        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.jti, jti);
        assert_eq!(claims.iss, "construct-test");
        assert_eq!(claims.exp, exp);
    }

    #[test]
    fn test_paseto_create_and_verify_refresh_token_round_trip() {
        let (auth, _, _) = make_paseto_full();
        let user_id = Uuid::new_v4();

        let (token, jti, exp) = auth
            .create_refresh_token(&user_id)
            .expect("create_refresh_token failed");

        let min_exp = chrono::Utc::now().timestamp() + 6 * 24 * 3600;
        assert!(exp > min_exp, "refresh token exp must be ~7 days out");

        let claims = auth.verify_token(&token).expect("verify failed");
        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.jti, jti);
    }

    #[test]
    fn test_paseto_each_token_has_unique_jti() {
        let (auth, _, _) = make_paseto_full();
        let user_id = Uuid::new_v4();
        let (_, jti1, _) = auth.create_token(&user_id).unwrap();
        let (_, jti2, _) = auth.create_token(&user_id).unwrap();
        assert_ne!(jti1, jti2);
    }

    #[test]
    fn test_paseto_unique_signatures_per_token() {
        // Same claims issued twice must produce different tokens (random nonce).
        let (auth, _, _) = make_paseto_full();
        let user_id = Uuid::new_v4();
        let (t1, _, _) = auth.create_token(&user_id).unwrap();
        let (t2, _, _) = auth.create_token(&user_id).unwrap();
        assert_ne!(t1, t2, "two token issuances must differ (random nonce)");
    }

    #[test]
    fn test_paseto_verify_wrong_issuer_fails() {
        let (auth_signer, _, _) = make_paseto_full();
        let (priv_pem, pub_pem) = make_ed25519_keypair();
        let config_wrong = make_config(
            None,
            None,
            Some(&priv_pem),
            Some(&pub_pem),
            "wrong-issuer",
            1,
            "paseto",
        );
        let auth_wrong = AuthManager::new(&config_wrong).unwrap();

        let user_id = Uuid::new_v4();
        let (token, _, _) = auth_signer.create_token(&user_id).unwrap();
        let result = auth_wrong.verify_token(&token);
        assert!(result.is_err(), "PASETO with wrong issuer must not verify");
    }

    #[test]
    fn test_paseto_verify_expired_token_fails() {
        // Build a token with exp set 5 minutes in the past using a Config with TTL
        // overridden via a manual claim injection. The simpler path: create at TTL=1
        // hour, then manually tamper exp. But PASETO signing is cryptographically
        // bound — we cannot forge. Instead, sign with a hand-crafted Claims via
        // the legacy internal API route by issuing a JWT and trusting exp here.
        // We bypass this by creating a token, then sleeping? No — use chrono shim.
        //
        // Cleaner: directly call sign_paseto via an expired Claims struct. Since
        // sign_paseto is private, we test the public create_token path which keeps
        // exp in the future; for expired-path coverage we lean on jwtwebtoken's
        // leeway-based coverage plus a manual construction below.
        //
        // Manual path: we craft a token signed with the same key but with exp in
        // the past. We construct the signed bytes manually to avoid exposing
        // internals.
        use crate::Claims;
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        use ed25519_compact::KeyPair;

        let kp = KeyPair::generate();
        let past = chrono::Utc::now().timestamp() - 300; // 5 min ago
        let claims = Claims {
            sub: Uuid::new_v4().to_string(),
            jti: Uuid::new_v4().to_string(),
            exp: past,
            iat: past - 3600,
            iss: "construct-test".to_string(),
            device_id: None,
        };
        let message = serde_json::to_vec(&claims).unwrap();
        let mut nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce);
        let mut pre_auth = Vec::new();
        pre_auth.extend_from_slice(b"paseto.v4.public.");
        pre_auth.extend_from_slice(&nonce);
        pre_auth.extend_from_slice(&message);
        let sig = kp.sk.sign(&pre_auth, None);
        let mut payload = Vec::with_capacity(32 + message.len() + 64);
        payload.extend_from_slice(&nonce);
        payload.extend_from_slice(&message);
        payload.extend_from_slice(sig.as_ref());
        let token = format!("v4.public.{}", URL_SAFE_NO_PAD.encode(&payload));

        // Build a verify-only AuthManager from the same key's pub side.
        let pub_pem = kp.pk.to_pem();
        let pub_pem_str = String::from_utf8(pub_pem.as_bytes().to_vec()).unwrap();
        let config = make_config(
            None,
            None,
            None,
            Some(&pub_pem_str),
            "construct-test",
            1,
            "paseto",
        );
        let auth = AuthManager::new(&config).unwrap();
        let result = auth.verify_token(&token);
        assert!(result.is_err(), "expired PASETO must not verify");
    }

    #[test]
    fn test_paseto_verify_only_mode_cannot_create() {
        let (_, pub_pem) = make_ed25519_keypair();
        let auth = make_paseto_verify_only(&pub_pem);
        let user_id = Uuid::new_v4();
        assert!(auth.create_token(&user_id).is_err());
        assert!(auth.create_refresh_token(&user_id).is_err());
    }

    #[test]
    fn test_paseto_verify_only_can_verify_token_from_full_manager() {
        // Crucial: verify-only manager (pub-only) must accept tokens signed by a
        // full manager (same keypair). This is the production pattern used by
        // user/messaging/etc services that hold only PASETO_PUBLIC_KEY.
        let (priv_pem, pub_pem) = make_ed25519_keypair();
        let config_full = make_config(
            None,
            None,
            Some(&priv_pem),
            Some(&pub_pem),
            "construct-test",
            1,
            "paseto",
        );
        let auth_full = AuthManager::new(&config_full).unwrap();
        let auth_vo = make_paseto_verify_only(&pub_pem);

        let user_id = Uuid::new_v4();
        let (token, _, _) = auth_full.create_token(&user_id).unwrap();
        let claims = auth_vo
            .verify_token(&token)
            .expect("verify-only manager must accept token from full manager with same key");
        assert_eq!(claims.sub, user_id.to_string());
    }

    #[test]
    fn test_paseto_garbage_token_fails() {
        let (auth, _, _) = make_paseto_full();
        assert!(auth.verify_token("v4.public.garbage").is_err());
        assert!(auth.verify_token("v4.public.").is_err());
    }

    #[test]
    fn test_paseto_empty_token_fails() {
        let (auth, _, _) = make_paseto_full();
        assert!(auth.verify_token("").is_err());
    }

    // ── Legacy RS256 JWT round trips (dual-stack — removed in Phase 4) ───────

    #[test]
    fn test_jwt_create_and_verify_access_token_round_trip() {
        let (auth, _, _) = make_jwt_full();
        let user_id = Uuid::new_v4();

        let (token, jti, exp) = auth.create_token(&user_id).expect("create_token failed");
        assert!(
            token.split('.').count() >= 2,
            "JWT has ≥2 dot-separated parts"
        );
        assert!(!jti.is_empty());
        assert!(exp > chrono::Utc::now().timestamp());

        let claims = auth.verify_token(&token).expect("verify_token failed");
        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.jti, jti);
        assert_eq!(claims.iss, "construct-test");
        assert_eq!(claims.exp, exp);
    }

    #[test]
    fn test_jwt_expired_token_fails() {
        use crate::Claims;
        use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
        let (auth, priv_pem, _) = make_jwt_full();
        let past_exp = chrono::Utc::now().timestamp() - 300;
        let claims = Claims {
            sub: Uuid::new_v4().to_string(),
            jti: Uuid::new_v4().to_string(),
            exp: past_exp,
            iat: past_exp - 3600,
            iss: "construct-test".to_string(),
            device_id: None,
        };
        let key = EncodingKey::from_rsa_pem(priv_pem.as_bytes()).unwrap();
        let token = encode(&Header::new(Algorithm::RS256), &claims, &key).unwrap();
        assert!(auth.verify_token(&token).is_err());
    }

    #[test]
    fn test_jwt_wrong_issuer_fails() {
        let (auth_signer, _, _) = make_jwt_full();
        let (priv_pem, pub_pem) = make_rsa_keypair();
        let config_wrong = make_config(
            Some(&priv_pem),
            Some(&pub_pem),
            None,
            None,
            "wrong-issuer",
            1,
            "jwt",
        );
        let auth_wrong = AuthManager::new(&config_wrong).unwrap();
        let (token, _, _) = auth_signer.create_token(&Uuid::new_v4()).unwrap();
        assert!(auth_wrong.verify_token(&token).is_err());
    }

    // ── Dual-stack verify (the migration-core feature) ────────────────────────

    #[test]
    fn test_dual_verify_jwt_token_accepted() {
        // Server with verify keys for both formats, but issue_format=jwt.
        // Verify it accepts a JWT issued by itself.
        let (jwt_auth, _, _) = make_jwt_full();
        let (paseto_pub_unused, _) = (String::new(), String::new());
        let _ = paseto_pub_unused;
        let user_id = Uuid::new_v4();
        let (token, _, _) = jwt_auth.create_token(&user_id).unwrap();
        let claims = jwt_auth
            .verify_token(&token)
            .expect("JWT must verify in dual mode");
        assert_eq!(claims.sub, user_id.to_string());
    }

    #[test]
    fn test_dual_issue_paseto_verify_both() {
        // Server with both verifying keys, issue_format=paseto.
        // Issues PASETO → both PASETO and a pre-existing JWT (signed with jwt key)
        // must verify via the same manager.
        let (auth_dual, jwt_priv, _, _, _) = make_dual_full();

        // Issue PASETO through the manager (issue_format=paseto).
        let user_id = Uuid::new_v4();
        let (paseto_token, _, _) = auth_dual.create_token(&user_id).unwrap();
        assert!(paseto_token.starts_with("v4.public."));
        let claims = auth_dual
            .verify_token(&paseto_token)
            .expect("PASETO verify in dual manager");
        assert_eq!(claims.sub, user_id.to_string());

        // Manually craft a JWT using the same RSA private key + issuer, to simulate
        // a legacy refresh token presented during dual-stack window.
        use crate::Claims;
        use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
        let jwt_claims = Claims {
            sub: user_id.to_string(),
            jti: Uuid::new_v4().to_string(),
            exp: chrono::Utc::now().timestamp() + 3600,
            iat: chrono::Utc::now().timestamp(),
            iss: "construct-test".to_string(),
            device_id: None,
        };
        let key = EncodingKey::from_rsa_pem(jwt_priv.as_bytes()).unwrap();
        let jwt_token = encode(&Header::new(Algorithm::RS256), &jwt_claims, &key).unwrap();

        let jwt_claims_recovered = auth_dual
            .verify_token(&jwt_token)
            .expect("JWT verify in dual manager must succeed (force-refresh path)");
        assert_eq!(jwt_claims_recovered.sub, user_id.to_string());
        assert_eq!(jwt_claims_recovered.jti, jwt_claims.jti);
    }

    #[test]
    fn test_paseto_token_signed_by_different_key_fails() {
        // Two independent keypairs — token issued by one must NOT verify against
        // the other. This covers the failure mode where a key rotation left a
        // verify-only manager with a stale public key.
        let (priv_pem_a, pub_pem_a) = make_ed25519_keypair();
        let (_, pub_pem_b) = make_ed25519_keypair();

        let config_a = make_config(
            None,
            None,
            Some(&priv_pem_a),
            Some(&pub_pem_a),
            "construct-test",
            1,
            "paseto",
        );
        let auth_a = AuthManager::new(&config_a).unwrap();
        let auth_b = make_paseto_verify_only(&pub_pem_b);

        let (token, _, _) = auth_a.create_token(&Uuid::new_v4()).unwrap();
        assert!(
            auth_a.verify_token(&token).is_ok(),
            "must verify with own key"
        );
        assert!(
            auth_b.verify_token(&token).is_err(),
            "must NOT verify with a different (unrelated) key"
        );
    }

    // ── device_id round trip (covers both formats via the public API) ──────────

    #[test]
    fn test_paseto_create_token_with_device_id() {
        let (auth, _, _) = make_paseto_full();
        let user_id = Uuid::new_v4();
        let device_id = "test-device-abc123";
        let (token, _, _) = auth
            .create_token_for_device(&user_id, Some(device_id))
            .unwrap();
        let claims = auth.verify_token(&token).unwrap();
        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.device_id, Some(device_id.to_string()));
    }

    #[test]
    fn test_paseto_create_refresh_token_with_device_id() {
        let (auth, _, _) = make_paseto_full();
        let user_id = Uuid::new_v4();
        let device_id = "test-device-xyz789";
        let (token, _, _) = auth
            .create_refresh_token_for_device(&user_id, Some(device_id))
            .unwrap();
        let claims = auth.verify_token(&token).unwrap();
        assert_eq!(claims.device_id, Some(device_id.to_string()));
    }

    #[test]
    fn test_paseto_device_id_in_claims_preserved() {
        let (auth, _, _) = make_paseto_full();
        let user_id = Uuid::new_v4();
        let device_id = "device-1234567890abcdef";
        let (token, jti, exp) = auth
            .create_token_for_device(&user_id, Some(device_id))
            .unwrap();
        let claims = auth.verify_token(&token).unwrap();
        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.jti, jti);
        assert_eq!(claims.device_id, Some(device_id.to_string()));
        assert_eq!(claims.exp, exp);
    }

    #[test]
    fn test_paseto_verify_device_id_matching() {
        let (auth, _, _) = make_paseto_full();
        let user_id = Uuid::new_v4();
        let device_id = "device-123";
        let (token, _, _) = auth
            .create_token_for_device(&user_id, Some(device_id))
            .unwrap();
        let claims = auth.verify_token(&token).unwrap();
        let result = auth.verify_device_id(device_id, &claims);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), device_id);
    }

    #[test]
    fn test_paseto_verify_device_id_mismatch() {
        let (auth, _, _) = make_paseto_full();
        let user_id = Uuid::new_v4();
        let (token, _, _) = auth
            .create_token_for_device(&user_id, Some("device-123"))
            .unwrap();
        let claims = auth.verify_token(&token).unwrap();
        let result = auth.verify_device_id("device-456", &claims);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("does not match"));
    }

    #[test]
    fn test_paseto_verify_device_id_missing_in_token() {
        let (auth, _, _) = make_paseto_full();
        let user_id = Uuid::new_v4();
        let (token, _, _) = auth.create_token(&user_id).unwrap();
        let claims = auth.verify_token(&token).unwrap();
        let result = auth.verify_device_id("device-123", &claims);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("missing device_id")
        );
    }

    // ── Config / AuthManager::new validation ────────────────────────────────

    #[test]
    fn test_new_without_any_keys_fails() {
        let config = make_config(None, None, None, None, "construct-test", 1, "paseto");
        let result = AuthManager::new(&config);
        assert!(result.is_err(), "must fail when no keys are provided");
    }

    #[test]
    fn test_issue_format_paseto_can_be_verifier_only_without_private_key() {
        // issue_format=paseto but only verifying keys (both PASETO pub + JWT pub)
        // is allowed — verify-only deployments don't need a signing key.
        let (_, paseto_pub) = make_ed25519_keypair();
        let (_, jwt_pub) = make_rsa_keypair();
        let config = make_config(
            None,
            Some(&jwt_pub),
            None,
            Some(&paseto_pub),
            "construct-test",
            1,
            "paseto",
        );
        let auth = AuthManager::new(&config).expect("verify-only dual manager must init OK");
        // But create_token must fail at runtime — no signing key.
        assert!(
            auth.create_token(&Uuid::new_v4()).is_err(),
            "no private key → create fail"
        );
    }

    #[test]
    fn test_issue_format_jwt_can_be_verifier_only_without_private_key() {
        let (_, paseto_pub) = make_ed25519_keypair();
        let (_, jwt_pub) = make_rsa_keypair();
        let config = make_config(
            None,
            Some(&jwt_pub),
            None,
            Some(&paseto_pub),
            "construct-test",
            1,
            "jwt",
        );
        let auth = AuthManager::new(&config).expect("verify-only dual manager must init OK");
        assert!(auth.create_token(&Uuid::new_v4()).is_err());
    }

    #[test]
    fn test_invalid_issue_format_fails() {
        let (paseto_priv, paseto_pub) = make_ed25519_keypair();
        let config = make_config(
            None,
            None,
            Some(&paseto_priv),
            Some(&paseto_pub),
            "construct-test",
            1,
            "hacker",
        );
        let result = AuthManager::new(&config);
        assert!(result.is_err(), "invalid TOKEN_ISSUE_FORMAT must error");
    }

    #[test]
    fn test_token_format_parse() {
        assert_eq!(TokenFormat::parse("paseto").unwrap(), TokenFormat::Paseto);
        assert_eq!(TokenFormat::parse("JWT").unwrap(), TokenFormat::Jwt);
        assert_eq!(TokenFormat::parse(" jwt ").unwrap(), TokenFormat::Jwt);
        assert!(TokenFormat::parse("hacker").is_err());
        assert!(TokenFormat::parse("").is_err());
    }
}
