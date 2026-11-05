//! Explicit test configuration; never loads an operator .env file.
use construct_config::Config;

pub(super) fn config() -> Config {
    let mut config = Config {
        database_url: std::env::var("DATABASE_URL").expect("DATABASE_URL required"),
        redis_url: std::env::var("REDIS_URL")
            .unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string()),
        bind_address: "127.0.0.1".to_string(),
        port: 8080,
        health_port: 8081,
        heartbeat_interval_secs: 60_i64,
        server_registry_ttl_secs: 120_i64,
        dedup_safety_margin_hours: 24,
        access_token_ttl_hours: 1,
        session_ttl_days: 30,
        refresh_token_ttl_days: 90,
        grpc_keepalive_interval_secs: 45,
        grpc_keepalive_timeout_secs: 5,
        token_issuer: "construct-test".to_string(),

        delivery_queue_prefix: "test_delivery_queue".to_string(),

        rust_log: "info".to_string(),
        messaging: construct_config::MessagingConfig::default(),
        logging: construct_config::LoggingConfig {
            enable_message_metadata: false,
            enable_user_identifiers: false,
            hash_salt: "test-salt-that-is-super-secret".to_string(),
        },
        security: construct_config::SecurityConfig {
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
            ip_rate_limiting_enabled: true,
            max_requests_per_ip_per_hour: 1000,
            combined_rate_limiting_enabled: true,
            max_requests_per_user_ip_per_hour: 500,
            max_long_poll_requests_per_window: 100,
            long_poll_rate_limit_window_secs: 60,

            metrics_auth_enabled: false,
            metrics_ip_whitelist: vec![],
            metrics_bearer_token: None,
            max_pow_challenges_per_hour: 5,
            max_registrations_per_hour: 3,
            pow_difficulty: 1, // Low difficulty for tests
            username_hmac_secret: vec![0u8; 32],
            contact_hmac_secret: vec![0u8; 32],
            request_envelope_key: vec![0u8; 32],
        },
        apns: construct_config::ApnsConfig {
            enabled: false,
            environment: construct_config::ApnsEnvironment::Development,
            key_path: "".to_string(),
            key_id: "".to_string(),
            team_id: "".to_string(),
            bundle_id: "".to_string(),
            topic: "".to_string(),
            voip_topic: None,
            device_token_encryption_key:
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
        },
        federation: construct_config::FederationConfig {
            enabled: false,
            instance_domain: "test.local".to_string(),
            base_domain: "test.local".to_string(),
            signing_key_seed: None,
            max_requests_per_origin_per_hour: 1000,
            mtls: construct_config::MtlsConfig {
                required: false,
                client_cert_path: None,
                client_key_path: None,
                verify_server_cert: false,
                pinned_certs: std::collections::HashMap::new(),
            },
        },
        db: construct_config::DbConfig {
            max_connections: 10,
            min_connections: 0,
            acquire_timeout_secs: 30,
            idle_timeout_secs: 600,
        },
        deeplinks: construct_config::DeepLinksConfig {
            apple_team_id: "".to_string(),
            android_package_name: "".to_string(),
            android_cert_fingerprint: "".to_string(),
        },
        redis_key_prefixes: construct_config::RedisKeyPrefixes {
            user: "user:".to_string(),
        },
        // Legacy aliases
        instance_domain: "test.local".to_string(),
        federation_base_domain: "test.local".to_string(),
        federation_enabled: false,
        deep_link_base_url: "".to_string(),
        paseto_private_key: None,
        paseto_public_key: None,
        paseto_public_key_previous: Vec::new(),
        media: construct_config::MediaConfig {
            enabled: false,
            base_url: "".to_string(),
            upload_token_secret: "".to_string(),
            max_file_size: 100 * 1024 * 1024,
            rate_limit_per_hour: 100,
        },

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
    let keys = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new([19; 32]));
    config.paseto_private_key = Some(keys.sk.to_pem());
    config.paseto_public_key = Some(keys.pk.to_pem());
    config
}
