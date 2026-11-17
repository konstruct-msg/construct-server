//! Contracts for `AppContext` construction.
//!
//! Two things are asserted here, and both are decisions the builder makes:
//!
//! 1. **What the builder accepts arrives unchanged.** Every `with_*` setter must
//!    deliver the *same* allocation into the built context. A setter that silently
//!    drops its value (or its receiver) would leave a service running against a
//!    different pool, queue, queue config or signer than the one it constructed,
//!    and nothing downstream would report it.
//! 2. **A missing dependency is named, in a fixed order.** `identity-service`
//!    adapts its own context through the builder and relies on `build()` returning
//!    an error naming the absent field rather than panicking or defaulting. The
//!    order matters because that message is what an operator sees at boot.
//!
//! The signer rules are a separate contract: a seed in config produces a signer
//! bound to the configured instance domain, an absent seed means "federation
//! signing disabled" (not an error), and a malformed seed disables signing rather
//! than aborting boot.
//!
//! Tests that need only a `Config` are ordinary `#[test]`s. Building a whole
//! context needs a live Redis for `MessageQueue::new`, so those are
//! `#[ignore = "requires Redis"]` and run in CI with `-- --ignored`.

use crate::{AppContext, AppContextBuilder};
use construct_apns::{ApnsClient, DeviceTokenEncryption};
use construct_auth::AuthManager;
use construct_config::{
    ApnsConfig, ApnsEnvironment, Config, DbConfig, DeepLinksConfig, FederationConfig,
    LoggingConfig, MediaConfig, MessagingConfig, MtlsConfig, RedisKeyPrefixes, SecurityConfig,
};
use construct_db::DbPool;
use construct_federation::ServerSigner;
use construct_queue::MessageQueue;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Base64 of 32 zero bytes: a structurally valid federation signing seed. Its value
/// is irrelevant to these tests, only that it parses.
const VALID_SEED: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

/// Minimal `Config` carrying no ambient environment. Built as a literal on purpose:
/// `Config::from_env` reads process-global variables, and a builder contract must not
/// depend on (or mutate) whatever the machine running the tests happens to export.
fn test_config() -> Config {
    // `AuthManager::new` refuses to run without a PASETO v4.public key pair; a fresh
    // throwaway pair per config keeps key material out of the repository.
    let (paseto_private_key, paseto_public_key) = {
        use ed25519_compact::KeyPair;
        let pair = KeyPair::generate();
        (
            Some(String::from_utf8(pair.sk.to_pem().as_bytes().to_vec()).expect("private PEM")),
            Some(String::from_utf8(pair.pk.to_pem().as_bytes().to_vec()).expect("public PEM")),
        )
    };

    Config {
        database_url: "postgres://test:test@127.0.0.1:1/test".to_string(),
        redis_url: "redis://127.0.0.1:6379".to_string(),
        paseto_private_key,
        paseto_public_key,
        paseto_public_key_previous: Vec::new(),
        port: 8080,
        bind_address: "127.0.0.1".to_string(),
        health_port: 8081,
        heartbeat_interval_secs: 60,
        server_registry_ttl_secs: 120,
        dedup_safety_margin_hours: 2,
        access_token_ttl_hours: 24,
        session_ttl_days: 30,
        refresh_token_ttl_days: 7,
        token_issuer: "construct-server".to_string(),
        delivery_queue_prefix: "delivery:".to_string(),
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
            user: "user:".to_string(),
        },
        media: MediaConfig {
            enabled: false,
            base_url: String::new(),
            upload_token_secret: String::new(),
            max_file_size: 10 * 1024 * 1024,
            rate_limit_per_hour: 100,
        },
        messaging: MessagingConfig::default(),
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

/// `AppContext` is not `Debug`, so `expect_err` cannot be used on the result.
fn build_error(builder: AppContextBuilder) -> String {
    match builder.build() {
        Ok(_) => panic!("builder reported success for an incomplete context"),
        Err(message) => message,
    }
}

/// A pool that is never used and never connected: these contracts cover what the
/// builder does with the handle, not what the database answers.
fn lazy_pool() -> DbPool {
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_lazy("postgres://nobody:nobody@127.0.0.1:1/none")
        .expect("lazy pool")
}

// ── Missing-dependency contract ───────────────────────────────────────────────

#[test]
fn builder_without_config_names_config() {
    assert_eq!(build_error(AppContext::builder()), "Config is required");
}

#[test]
fn builder_with_config_only_names_db_pool() {
    let builder = AppContext::builder().with_config(Arc::new(test_config()));
    assert_eq!(build_error(builder), "db_pool is required");
}

// ── Signer contract ───────────────────────────────────────────────────────────

#[test]
fn signer_is_absent_without_a_seed() {
    let mut config = test_config();
    config.federation.signing_key_seed = None;
    assert!(
        AppContext::init_server_signer_pub(&config).is_none(),
        "federation signing must stay disabled when no seed is configured"
    );
}

#[test]
fn signer_is_present_with_a_seed_and_carries_the_instance_domain() {
    let mut config = test_config();
    config.federation.signing_key_seed = Some(VALID_SEED.to_string());
    config.federation.instance_domain = "origin.example".to_string();

    let signer =
        AppContext::init_server_signer_pub(&config).expect("a valid seed must produce a signer");
    // The domain is what a peer checks when it verifies the signature: a signer
    // built with the wrong domain signs for an identity it does not own.
    assert_eq!(signer.instance_domain(), "origin.example");
}

#[test]
fn private_signer_helper_matches_the_public_one() {
    let mut config = test_config();
    config.federation.signing_key_seed = Some(VALID_SEED.to_string());
    config.federation.instance_domain = "origin.example".to_string();

    let signer =
        AppContext::init_server_signer(&config).expect("a valid seed must produce a signer");
    assert_eq!(signer.instance_domain(), "origin.example");
}

#[test]
fn malformed_seed_disables_signing_instead_of_failing_boot() {
    for broken in ["not base64 !!", "AAAA", ""] {
        let mut config = test_config();
        config.federation.signing_key_seed = Some(broken.to_string());
        assert!(
            AppContext::init_server_signer_pub(&config).is_none(),
            "seed {broken:?} must disable federation signing, not panic or build a signer"
        );
    }
}

// ── Full builder contract (requires Redis) ────────────────────────────────────

#[tokio::test]
#[ignore = "requires Redis"]
async fn build_carries_every_accepted_field() {
    let mut config = test_config();
    // A seed in config proves the explicit override wins, rather than merely being
    // the only source available.
    config.federation.signing_key_seed = Some(VALID_SEED.to_string());
    config.federation.instance_domain = "config.example".to_string();
    let config = Arc::new(config);

    let db_pool = Arc::new(lazy_pool());
    let queue = Arc::new(Mutex::new(MessageQueue::new(&config).await.expect("redis")));
    let auth_manager = Arc::new(AuthManager::new(&config).expect("auth manager"));
    let apns_client = Arc::new(ApnsClient::new(config.apns.clone()).expect("apns client"));
    let token_encryption =
        Arc::new(DeviceTokenEncryption::from_hex(&"0".repeat(64)).expect("token encryption"));
    let signer = Arc::new(
        ServerSigner::from_seed_base64(VALID_SEED, "override.example".to_string())
            .expect("override signer"),
    );

    let context = AppContext::builder()
        .with_db_pool(db_pool.clone())
        .with_queue(queue.clone())
        .with_auth_manager(auth_manager.clone())
        .with_config(config.clone())
        .with_apns_client(apns_client.clone())
        .with_token_encryption(token_encryption.clone())
        .with_server_instance_id("instance-abc".to_string())
        .with_server_signer(signer.clone())
        .build()
        .expect("every required field was supplied");

    assert!(Arc::ptr_eq(&context.db_pool, &db_pool));
    assert!(Arc::ptr_eq(&context.queue, &queue));
    assert!(Arc::ptr_eq(&context.auth_manager, &auth_manager));
    assert!(Arc::ptr_eq(&context.config, &config));
    assert!(Arc::ptr_eq(
        context.apns_client.as_ref().expect("apns client"),
        &apns_client
    ));
    assert!(Arc::ptr_eq(
        context.token_encryption.as_ref().expect("token encryption"),
        &token_encryption
    ));
    assert_eq!(context.server_instance_id, "instance-abc");
    assert!(
        Arc::ptr_eq(context.server_signer.as_ref().expect("signer"), &signer),
        "an explicit signer must not be replaced by the config-derived one"
    );
    assert_eq!(
        context
            .server_signer
            .as_ref()
            .expect("signer")
            .instance_domain(),
        "override.example"
    );

    // The remote-key cache belongs to the context that will use it. Sharing it across
    // builds would let one service's cached peer key answer another's verification.
    let second = AppContext::builder()
        .with_db_pool(db_pool.clone())
        .with_queue(queue.clone())
        .with_auth_manager(auth_manager.clone())
        .with_config(config.clone())
        .with_server_instance_id("instance-def".to_string())
        .build()
        .expect("build");
    assert!(!Arc::ptr_eq(
        &context.public_key_cache,
        &second.public_key_cache
    ));
    assert!(second.apns_client.is_none());
    assert!(second.token_encryption.is_none());
}

#[tokio::test]
#[ignore = "requires Redis"]
async fn missing_required_fields_are_named_in_build_order() {
    let config = Arc::new(test_config());
    let queue = Arc::new(Mutex::new(MessageQueue::new(&config).await.expect("redis")));
    let auth_manager = Arc::new(AuthManager::new(&config).expect("auth manager"));

    // Each case supplies everything the builder accepts *before* the field under
    // test. A setter that dropped its receiver would lose those earlier fields too,
    // and the reported name would move — which is exactly what must not happen.
    assert_eq!(
        build_error(
            AppContext::builder()
                .with_db_pool(Arc::new(lazy_pool()))
                .with_config(config.clone())
        ),
        "queue is required"
    );
    assert_eq!(
        build_error(
            AppContext::builder()
                .with_db_pool(Arc::new(lazy_pool()))
                .with_queue(queue.clone())
                .with_config(config.clone())
        ),
        "auth_manager is required"
    );
    assert_eq!(
        build_error(
            AppContext::builder()
                .with_db_pool(Arc::new(lazy_pool()))
                .with_queue(queue.clone())
                .with_auth_manager(auth_manager.clone())
                .with_config(config.clone())
        ),
        "server_instance_id is required"
    );
}
