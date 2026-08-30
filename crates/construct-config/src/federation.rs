// ============================================================================
// Federation and APNs Configuration
// ============================================================================
// Phase 2.8: Extracted from config.rs for better organization

use anyhow::Result;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use std::collections::HashMap;

/// mTLS configuration for federation
#[derive(Clone, Debug)]
pub struct MtlsConfig {
    /// Whether mTLS is required for S2S connections
    pub required: bool,
    /// Path to client certificate for outgoing connections
    pub client_cert_path: Option<String>,
    /// Path to client key for outgoing connections
    pub client_key_path: Option<String>,
    /// Whether to verify server certificates (should be true in production)
    pub verify_server_cert: bool,
    /// Pinned certificate fingerprints for known federation partners
    /// Map of domain -> SHA256 fingerprint
    pub pinned_certs: HashMap<String, String>,
}

impl Default for MtlsConfig {
    fn default() -> Self {
        Self {
            required: false,
            client_cert_path: None,
            client_key_path: None,
            verify_server_cert: true,
            pinned_certs: HashMap::new(),
        }
    }
}

/// APNs environment
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApnsEnvironment {
    Production,
    Development,
}

impl std::str::FromStr for ApnsEnvironment {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "production" | "prod" => Ok(Self::Production),
            "development" | "dev" | "sandbox" => Ok(Self::Development),
            _ => anyhow::bail!(
                "Invalid APNs environment: {}. Must be 'production' or 'development'/'sandbox'",
                s
            ),
        }
    }
}

impl ApnsEnvironment {
    /// Canonical name used in the `push_environment` DB columns and on the wire.
    ///
    /// Note the spelling difference from the config/entitlement vocabulary: Apple calls
    /// the build setting "development" but the endpoint "sandbox". Both parse; this is
    /// what we store.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Production => "production",
            Self::Development => "sandbox",
        }
    }
}

/// One or more APNs environments, in probe order.
///
/// Parses a single value (`"production"`) **or** a comma-separated list
/// (`"sandbox,production"`). Accepts either spelling of the sandbox endpoint —
/// `sandbox` / `development` / `dev` — and `prod` for production.
///
/// A single value asserts which endpoint a token belongs to; the pair admits that it is
/// unknown and both must be tried. That distinction matters because APNs answers
/// `BadDeviceToken` both for a genuinely dead token and for a live token sent to the
/// wrong endpoint — so a caller that guesses wrong cannot tell the two apart, and will
/// happily delete a working token. Anything that cannot know the environment should
/// record [`ApnsEnvironments::both`] rather than guess.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApnsEnvironments(Vec<ApnsEnvironment>);

impl ApnsEnvironments {
    /// Both endpoints, sandbox first. The correct value whenever the environment is unknown.
    pub fn both() -> Self {
        Self(vec![
            ApnsEnvironment::Development,
            ApnsEnvironment::Production,
        ])
    }

    pub fn single(env: ApnsEnvironment) -> Self {
        Self(vec![env])
    }

    /// Parse, falling back to [`Self::both`] on anything unrecognised or empty.
    ///
    /// Use this for values read back from storage, where rejecting the row would mean
    /// dropping a push; use `FromStr` for operator-supplied config, where a typo should
    /// be loud.
    pub fn parse_or_both(raw: &str) -> Self {
        raw.parse().unwrap_or_else(|_| Self::both())
    }

    pub fn iter(&self) -> impl Iterator<Item = ApnsEnvironment> + '_ {
        self.0.iter().cloned()
    }

    pub fn contains(&self, env: &ApnsEnvironment) -> bool {
        self.0.contains(env)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::str::FromStr for ApnsEnvironments {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let mut out: Vec<ApnsEnvironment> = Vec::with_capacity(2);
        for part in s.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let env: ApnsEnvironment = part.parse()?;
            if !out.contains(&env) {
                out.push(env);
            }
        }
        if out.is_empty() {
            anyhow::bail!("Empty APNs environment list: {:?}", s);
        }
        Ok(Self(out))
    }
}

impl std::fmt::Display for ApnsEnvironments {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let joined: Vec<&str> = self.0.iter().map(ApnsEnvironment::as_str).collect();
        f.write_str(&joined.join(","))
    }
}

/// APNs (Apple Push Notification service) configuration
#[derive(Clone, Debug)]
pub struct ApnsConfig {
    /// Whether APNs is enabled (default: false)
    pub enabled: bool,
    /// APNs environment: "production" or "development"
    pub environment: ApnsEnvironment,
    /// Path to .p8 authentication key file
    pub key_path: String,
    /// APNs Key ID (10 characters)
    pub key_id: String,
    /// APNs Team ID
    pub team_id: String,
    /// iOS app Bundle ID
    pub bundle_id: String,
    /// APNs topic (usually same as bundle_id)
    pub topic: String,
    /// VoIP APNs topic (PushKit), e.g. "<bundle_id>.voip"
    ///
    /// If unset, VoIP pushes are disabled (and callers may fall back to
    /// returning CALLEE_OFFLINE without wake).
    pub voip_topic: Option<String>,
    /// Encryption key for device tokens in database (32 bytes hex = 64 chars)
    pub device_token_encryption_key: String,
}

impl ApnsConfig {
    pub(crate) fn from_env() -> anyhow::Result<Self> {
        let apns_enabled = std::env::var("APNS_ENABLED")
            .unwrap_or_else(|_| "false".to_string())
            .parse()
            .unwrap_or(false);

        // SECURITY: Device token encryption key must be the same across all services
        // that store or read encrypted tokens (notification-service, messaging-service,
        // auth-service). An ephemeral per-process key causes cross-service AEAD failures.
        // Fail fast if APNS is enabled and the key is missing.
        //
        // Strip surrounding quotes: Docker env_file passes them literally when the
        // Vault agent template writes values as KEY="value". Shell strips quotes but
        // env_file does not.
        let key = match std::env::var("APNS_DEVICE_TOKEN_ENCRYPTION_KEY")
            .map(|k| k.trim_matches('"').trim_matches('\'').to_string())
        {
            Ok(k) if k.len() == 64 && k.chars().all(|c| c.is_ascii_hexdigit()) => k,
            Ok(_) if apns_enabled => {
                anyhow::bail!(
                    "APNS_DEVICE_TOKEN_ENCRYPTION_KEY must be 64 hex characters (32 bytes). \
                    Generate with: openssl rand -hex 32"
                );
            }
            Err(_) if apns_enabled => {
                // Key missing and APNS enabled: always fatal regardless of environment,
                // because all services must share the exact same key.
                anyhow::bail!(
                    "APNS_DEVICE_TOKEN_ENCRYPTION_KEY is required when APNS_ENABLED=true. \
                    Each service generates a different ephemeral key causing cross-service \
                    decryption failures. Generate once and persist: openssl rand -hex 32"
                );
            }
            Err(_) => {
                // APNS disabled: use a fixed dev placeholder (never used to encrypt real tokens)
                "0000000000000000000000000000000000000000000000000000000000000000".to_string()
            }
            Ok(_) => {
                // Invalid format, APNS disabled: use placeholder with warning
                tracing::warn!(
                    "APNS_DEVICE_TOKEN_ENCRYPTION_KEY is set but not valid 64 hex chars — \
                    ignored (APNS_ENABLED=false). Fix with: openssl rand -hex 32"
                );
                "0000000000000000000000000000000000000000000000000000000000000000".to_string()
            }
        };

        Ok(Self {
            enabled: apns_enabled,
            environment: std::env::var("APNS_ENVIRONMENT")
                .unwrap_or_else(|_| "development".to_string())
                .parse()
                .unwrap_or(ApnsEnvironment::Development),
            key_path: std::env::var("APNS_KEY_PATH")
                .unwrap_or_else(|_| "AuthKey_XXXXXXXXXX.p8".to_string()),
            key_id: std::env::var("APNS_KEY_ID").unwrap_or_else(|_| "XXXXXXXXXX".to_string()),
            team_id: std::env::var("APNS_TEAM_ID").unwrap_or_else(|_| "XXXXXXXXXX".to_string()),
            bundle_id: std::env::var("APNS_BUNDLE_ID")
                .unwrap_or_else(|_| "com.example.construct".to_string()),
            topic: std::env::var("APNS_TOPIC")
                .ok()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| {
                    std::env::var("APNS_BUNDLE_ID")
                        .unwrap_or_else(|_| "com.example.construct".to_string())
                }),
            voip_topic: std::env::var("APNS_VOIP_TOPIC")
                .ok()
                .filter(|s| !s.is_empty())
                .or_else(|| {
                    std::env::var("APNS_VOIP_BUNDLE_ID")
                        .ok()
                        .filter(|s| !s.is_empty())
                }),
            device_token_encryption_key: key,
        })
    }

    /// This config re-pointed at the APNs sandbox endpoint (api.sandbox.push.apple.com).
    ///
    /// Apple lets an APNs auth key be restricted to a single environment. A
    /// Production-only key is accepted on api.push.apple.com and rejected on the
    /// sandbox endpoint with `BadEnvironmentKeyInToken` (403) — which is exactly how
    /// every push to a development build died while production users saw nothing wrong.
    ///
    /// Preferred fix is one key configured for "Sandbox & Production", in which case
    /// nothing here needs setting. `APNS_SANDBOX_KEY_PATH` / `APNS_SANDBOX_KEY_ID` are
    /// the escape hatch for teams that would rather keep the production key untouched
    /// and issue a separate sandbox-scoped key; both default to the production key.
    pub fn sandbox_variant(&self) -> Self {
        let non_empty = |var: &str| {
            std::env::var(var)
                .ok()
                .map(|v| v.trim_matches('"').trim_matches('\'').to_string())
                .filter(|v| !v.is_empty())
        };

        Self {
            environment: ApnsEnvironment::Development,
            key_path: non_empty("APNS_SANDBOX_KEY_PATH").unwrap_or_else(|| self.key_path.clone()),
            key_id: non_empty("APNS_SANDBOX_KEY_ID").unwrap_or_else(|| self.key_id.clone()),
            ..self.clone()
        }
    }
}

/// Federation configuration
#[derive(Clone, Debug)]
pub struct FederationConfig {
    /// Instance domain (e.g., "eu.konstruct.cc")
    pub instance_domain: String,
    /// Base federation domain (e.g., "konstruct.cc")
    pub base_domain: String,
    /// Whether federation is enabled
    pub enabled: bool,
    /// Server signing key seed (base64-encoded 32 bytes for Ed25519)
    /// Generate with: openssl rand -base64 32
    pub signing_key_seed: Option<String>,
    /// mTLS configuration for S2S federation
    pub mtls: MtlsConfig,
    /// Max inbound requests per origin server per hour (sliding window).
    /// Default: 1000. Zero or negative disables per-origin rate limiting.
    pub max_requests_per_origin_per_hour: i64,
}

impl FederationConfig {
    pub(crate) fn from_env() -> anyhow::Result<Self> {
        // INSTANCE_DOMAIN is REQUIRED — no silent default. It goes into the
        // SenderCertificate payload (`userID ‖ domain ‖ …`), the federation origin,
        // invite links, and the federation id (`user@domain`). The previous
        // `eu.konstruct.cc` fallback let services disagree on their own domain when the
        // var was set on only some of them (2026-07-13: identity=ams vs messaging=eu,
        // because messaging's compose block omitted INSTANCE_DOMAIN). Fail loud so a
        // missing value is a boot error, never a silently-wrong domain.
        let instance_domain = std::env::var("INSTANCE_DOMAIN")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "INSTANCE_DOMAIN is required but unset/empty. Set it (e.g. \
                     ams.konstruct.cc) identically on EVERY service — it is part of \
                     SenderCertificates, invite links, and the federation id."
                )
            })?;
        // NOTE: FEDERATION_BASE_DOMAIN still defaults to "konstruct.cc" — a separate
        // hardcode, left as a follow-up (only relevant when federation is enabled).
        let base_domain =
            std::env::var("FEDERATION_BASE_DOMAIN").unwrap_or_else(|_| "konstruct.cc".to_string());
        let enabled = std::env::var("FEDERATION_ENABLED")
            .unwrap_or_else(|_| "false".to_string())
            .parse()
            .unwrap_or(false);
        let signing_key_seed = std::env::var("SERVER_SIGNING_KEY").ok();

        // SECURITY: Federation signing key is REQUIRED if federation is enabled
        // Disable federation if key is missing rather than allowing unsigned messages
        let (enabled, signing_key_seed) = if enabled && signing_key_seed.is_none() {
            tracing::error!(
                "FEDERATION_ENABLED=true but SERVER_SIGNING_KEY is not set. \
                 Federation will be DISABLED for security. \
                 Generate key with: openssl rand -base64 32"
            );
            (false, None)
        } else if enabled {
            // Validate signing key strength if provided
            if let Some(ref key) = signing_key_seed {
                // Base64-encoded 32 bytes should be 44 characters (without padding) or 43-44 with padding
                // Use the same validation logic as ServerSigner::from_seed_base64
                let decoded = match BASE64.decode(key.trim()) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        anyhow::bail!("SERVER_SIGNING_KEY is not valid base64: {}", e);
                    }
                };
                if decoded.len() != 32 {
                    anyhow::bail!(
                        "SERVER_SIGNING_KEY must decode to exactly 32 bytes (got {} bytes). \
                         Generate with: openssl rand -base64 32",
                        decoded.len()
                    );
                }
            }
            (true, signing_key_seed)
        } else {
            (false, signing_key_seed)
        };

        // Parse pinned certificates from environment variable
        // Format: "domain1:fingerprint1,domain2:fingerprint2"
        let pinned_certs = std::env::var("FEDERATION_PINNED_CERTS")
            .ok()
            .map(|certs_str| {
                let mut pinned = std::collections::HashMap::new();
                for entry in certs_str.split(',') {
                    let parts: Vec<&str> = entry.split(':').collect();
                    if parts.len() == 2 {
                        let domain = parts[0].trim().to_string();
                        let fingerprint = parts[1].trim().to_string();
                        if !domain.is_empty() && !fingerprint.is_empty() {
                            pinned.insert(domain, fingerprint);
                        }
                    }
                }
                pinned
            })
            .unwrap_or_default();

        let max_requests_per_origin_per_hour = std::env::var("FEDERATION_MAX_PER_ORIGIN_PER_HOUR")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1000);

        Ok(Self {
            instance_domain,
            base_domain,
            enabled,
            signing_key_seed,
            mtls: MtlsConfig {
                required: std::env::var("FEDERATION_MTLS_REQUIRED")
                    .unwrap_or_else(|_| "false".to_string())
                    .parse()
                    .unwrap_or(false),
                client_cert_path: std::env::var("FEDERATION_CLIENT_CERT_PATH").ok(),
                client_key_path: std::env::var("FEDERATION_CLIENT_KEY_PATH").ok(),
                verify_server_cert: std::env::var("FEDERATION_VERIFY_SERVER_CERT")
                    .unwrap_or_else(|_| "true".to_string())
                    .parse()
                    .unwrap_or(true),
                pinned_certs,
            },
            max_requests_per_origin_per_hour,
        })
    }
}

#[cfg(test)]
mod apns_environment_tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn parses_single_value_and_both_sandbox_spellings() {
        assert_eq!(
            ApnsEnvironments::from_str("production").unwrap(),
            ApnsEnvironments::single(ApnsEnvironment::Production)
        );
        for spelling in ["sandbox", "development", "dev", "SANDBOX", " Sandbox "] {
            assert_eq!(
                ApnsEnvironments::from_str(spelling).unwrap(),
                ApnsEnvironments::single(ApnsEnvironment::Development),
                "failed for {spelling:?}"
            );
        }
    }

    #[test]
    fn parses_a_list_and_preserves_declared_probe_order() {
        assert_eq!(
            ApnsEnvironments::from_str("sandbox,production").unwrap(),
            ApnsEnvironments::both()
        );
        // The caller's order is the probe order — the likelier endpoint goes first.
        assert_eq!(
            ApnsEnvironments::from_str("production, sandbox")
                .unwrap()
                .iter()
                .collect::<Vec<_>>(),
            vec![ApnsEnvironment::Production, ApnsEnvironment::Development]
        );
    }

    #[test]
    fn deduplicates_and_tolerates_untidy_input() {
        let parsed = ApnsEnvironments::from_str(" production , prod,, production ").unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed.to_string(), "production");
    }

    #[test]
    fn rejects_garbage_but_parse_or_both_never_guesses_one() {
        assert!(ApnsEnvironments::from_str("staging").is_err());
        assert!(ApnsEnvironments::from_str("").is_err());
        assert!(ApnsEnvironments::from_str(" , ").is_err());

        // Storage values must not blow up a send, and must never collapse to a single
        // guess — the wrong guess is what gets a live token deleted.
        for garbage in ["", "staging", "???", " , "] {
            assert_eq!(
                ApnsEnvironments::parse_or_both(garbage),
                ApnsEnvironments::both(),
                "failed for {garbage:?}"
            );
        }
        // A valid value still survives the lenient path.
        assert_eq!(
            ApnsEnvironments::parse_or_both("production"),
            ApnsEnvironments::single(ApnsEnvironment::Production)
        );
    }

    #[test]
    fn display_round_trips_through_the_db_spelling() {
        // Config says "development", the column and the endpoint say "sandbox".
        assert_eq!(ApnsEnvironment::Development.as_str(), "sandbox");
        for raw in ["production", "sandbox", "sandbox,production"] {
            let parsed = ApnsEnvironments::from_str(raw).unwrap();
            assert_eq!(
                ApnsEnvironments::from_str(&parsed.to_string()).unwrap(),
                parsed
            );
        }
        assert_eq!(
            ApnsEnvironments::from_str("dev,prod").unwrap().to_string(),
            "sandbox,production"
        );
    }
}
