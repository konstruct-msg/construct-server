// ============================================================================
// Per-service required secrets
// ============================================================================
//
// `Config::from_env()` used to demand DATABASE_URL, REDIS_URL, the HMAC trio,
// LOG_HASH_SALT and CSRF_SECRET of every binary that called it. That forced
// media/gateway/quic to hold identity keys they never use.
//
// Present-but-malformed still fails everywhere (`secret_hygiene::validate`).
// Absent + not needed → empty, never the insecure default.
// Absent + needed + production → refused boot.
//
// See construct-docs decisions/secrets-are-sliced-not-shared.md

/// Which secrets this process may require at boot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecretNeeds {
    pub database_url: bool,
    pub redis_url: bool,
    pub username_hmac: bool,
    pub contact_hmac: bool,
    pub request_envelope: bool,
    /// Receipt-routing hash in messaging, plus `log_safe_id` in identity.
    pub log_hash_salt: bool,
    pub csrf: bool,
}

impl SecretNeeds {
    /// Every loader-required secret. Tests and anything that still calls
    /// [`crate::Config::from_env`] use this so behaviour stays as before.
    pub const ALL: Self = Self {
        database_url: true,
        redis_url: true,
        username_hmac: true,
        contact_hmac: true,
        request_envelope: true,
        log_hash_salt: true,
        csrf: true,
    };

    pub const IDENTITY: Self = Self {
        database_url: true,
        redis_url: true,
        username_hmac: true,
        contact_hmac: true,
        request_envelope: true,
        log_hash_salt: true,
        csrf: false,
    };

    pub const MESSAGING: Self = Self {
        database_url: true,
        redis_url: true,
        username_hmac: false,
        contact_hmac: false,
        request_envelope: false,
        log_hash_salt: true,
        csrf: false,
    };

    pub const KEY: Self = Self {
        database_url: true,
        redis_url: true,
        username_hmac: false,
        contact_hmac: false,
        request_envelope: false,
        log_hash_salt: false,
        csrf: false,
    };

    pub const GROUP: Self = Self {
        database_url: true,
        redis_url: true,
        username_hmac: false,
        contact_hmac: false,
        request_envelope: false,
        log_hash_salt: false,
        csrf: false,
    };

    pub const MEDIA: Self = Self {
        database_url: true,
        redis_url: false,
        username_hmac: false,
        contact_hmac: false,
        request_envelope: false,
        log_hash_salt: false,
        csrf: false,
    };

    /// Signaling reads DATABASE_URL / REDIS_URL / CONTACT_HMAC itself.
    /// Config here is only for AuthManager (PASETO/JWT public keys).
    pub const SIGNALING: Self = Self {
        database_url: false,
        redis_url: false,
        username_hmac: false,
        contact_hmac: false,
        request_envelope: false,
        log_hash_salt: false,
        csrf: false,
    };

    pub const GATEWAY: Self = Self {
        database_url: false,
        redis_url: false,
        username_hmac: false,
        contact_hmac: false,
        request_envelope: false,
        log_hash_salt: false,
        csrf: false,
    };

    pub const VEIL: Self = Self {
        database_url: true,
        redis_url: false,
        username_hmac: false,
        contact_hmac: false,
        request_envelope: false,
        log_hash_salt: false,
        csrf: false,
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Config;
    use std::sync::{Mutex, MutexGuard};

    static ENV: Mutex<()> = Mutex::new(());

    const HMAC: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SALT: &str = "unique-log-hash-salt-for-secret-needs-tests";

    struct EnvGuard {
        _lock: MutexGuard<'static, ()>,
        saved: Vec<(String, Option<String>)>,
    }

    impl EnvGuard {
        fn lock(keys: &[&str]) -> Self {
            let _lock = ENV.lock().unwrap_or_else(|e| e.into_inner());
            let saved = keys
                .iter()
                .map(|k| ((*k).to_string(), std::env::var(k).ok()))
                .collect();
            Self { _lock, saved }
        }

        fn set(&self, k: &str, v: &str) {
            // SAFETY: held behind ENV; restored on Drop.
            unsafe { std::env::set_var(k, v) }
        }

        /// Empty, not unset: `dotenvy::dotenv()` would restore an unset var from `.env`.
        fn blank(&self, k: &str) {
            unsafe { std::env::set_var(k, "") }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (k, v) in &self.saved {
                unsafe {
                    match v {
                        Some(val) => std::env::set_var(k, val),
                        None => std::env::remove_var(k),
                    }
                }
            }
        }
    }

    fn keys() -> &'static [&'static str] {
        &[
            "ENVIRONMENT",
            "ALLOW_INSECURE_SECRETS",
            "PRODUCTION",
            "DATABASE_URL",
            "REDIS_URL",
            "INSTANCE_DOMAIN",
            "USERNAME_HMAC_SECRET",
            "CONTACT_HMAC_SECRET",
            "REQUEST_ENVELOPE_KEY",
            "LOG_HASH_SALT",
            "CSRF_SECRET",
            "CSRF_ENABLED",
            "SERVER_SIGNING_KEY",
            "TOKEN_ISSUER_KEY",
            "PASETO_PRIVATE_KEY",
            "APNS_ENABLED",
            "APNS_DEVICE_TOKEN_ENCRYPTION_KEY",
            "BUNDLE_SIGNING_KEY",
            "BUNDLE_SIGNING_PUBLIC_KEY",
            "MEDIA_ENABLED",
        ]
    }

    fn prod_without_hmac(env: &EnvGuard) {
        env.set("ENVIRONMENT", "production");
        env.blank("ALLOW_INSECURE_SECRETS");
        env.blank("PRODUCTION");
        env.set("INSTANCE_DOMAIN", "test.local");
        env.set("DATABASE_URL", "postgres://u:p@localhost/db");
        env.set("REDIS_URL", "redis://localhost");
        env.set("LOG_HASH_SALT", SALT);
        env.set("CSRF_SECRET", "csrf-secret-at-least-32-characters-ok");
        env.blank("APNS_ENABLED");
        env.blank("MEDIA_ENABLED");
        env.blank("USERNAME_HMAC_SECRET");
        env.blank("CONTACT_HMAC_SECRET");
        env.blank("REQUEST_ENVELOPE_KEY");
        env.blank("PASETO_PRIVATE_KEY");
        env.blank("TOKEN_ISSUER_KEY");
        env.blank("SERVER_SIGNING_KEY");
        env.blank("BUNDLE_SIGNING_KEY");
        env.blank("BUNDLE_SIGNING_PUBLIC_KEY");
        // Empty, not a valid-looking leftover: GitHub Actions YAML coerced an
        // unquoted 64-zero literal to integer `0`, and hygiene then failed
        // "must be exactly 64 hex chars" before SecretNeeds could run.
        env.blank("APNS_DEVICE_TOKEN_ENCRYPTION_KEY");
    }

    #[test]
    fn identity_refuses_missing_hmac_in_production() {
        let env = EnvGuard::lock(keys());
        prod_without_hmac(&env);
        let err = Config::from_env_for(SecretNeeds::IDENTITY)
            .expect_err("identity must refuse a missing USERNAME_HMAC_SECRET");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("USERNAME_HMAC_SECRET"),
            "expected HMAC requirement, got: {msg}"
        );
    }

    #[test]
    fn media_boots_without_hmac_issuer_or_paseto_private() {
        let env = EnvGuard::lock(keys());
        prod_without_hmac(&env);
        env.blank("REDIS_URL");
        let cfg = Config::from_env_for(SecretNeeds::MEDIA)
            .expect("media must boot without HMAC / TOKEN_ISSUER_KEY / PASETO_PRIVATE_KEY");
        assert!(cfg.security.username_hmac_secret.is_empty());
        assert!(cfg.security.contact_hmac_secret.is_empty());
        assert!(cfg.security.request_envelope_key.is_empty());
        assert!(cfg.paseto_private_key.is_none() || cfg.paseto_private_key.as_deref() == Some(""));
        assert!(cfg.redis_url.is_empty());
        assert_eq!(cfg.database_url, "postgres://u:p@localhost/db");
    }

    #[test]
    fn gateway_boots_without_database_url() {
        let env = EnvGuard::lock(keys());
        prod_without_hmac(&env);
        env.blank("DATABASE_URL");
        env.blank("REDIS_URL");
        let cfg = Config::from_env_for(SecretNeeds::GATEWAY)
            .expect("gateway must boot without DATABASE_URL / REDIS_URL / HMAC");
        assert!(cfg.database_url.is_empty());
        assert!(cfg.redis_url.is_empty());
    }

    #[test]
    fn quoted_server_signing_key_fails_even_for_messaging() {
        let env = EnvGuard::lock(keys());
        prod_without_hmac(&env);
        env.set("USERNAME_HMAC_SECRET", HMAC);
        env.set("CONTACT_HMAC_SECRET", HMAC);
        env.set("REQUEST_ENVELOPE_KEY", HMAC);
        env.set(
            "SERVER_SIGNING_KEY",
            "\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"",
        );
        let err = Config::from_env_for(SecretNeeds::MESSAGING)
            .expect_err("quoted SERVER_SIGNING_KEY must fail hygiene, not be ignored");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("SERVER_SIGNING_KEY"),
            "expected quote rejection, got: {msg}"
        );
    }

    #[test]
    fn identity_accepts_present_hmac_in_production() {
        let env = EnvGuard::lock(keys());
        prod_without_hmac(&env);
        env.set("USERNAME_HMAC_SECRET", HMAC);
        env.set("CONTACT_HMAC_SECRET", HMAC);
        env.set("REQUEST_ENVELOPE_KEY", HMAC);
        Config::from_env_for(SecretNeeds::IDENTITY)
            .expect("identity must boot when HMAC trio + DB/Redis/salt are set");
    }
}
