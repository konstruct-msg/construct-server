// ============================================================================
// Logging Configuration
// ============================================================================
// Phase 2.8: Extracted from config.rs for better organization

#[derive(Clone, Debug)]
pub struct LoggingConfig {
    pub enable_message_metadata: bool,
    pub enable_user_identifiers: bool,
    pub hash_salt: String,
}

impl LoggingConfig {
    pub(crate) fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            enable_message_metadata: std::env::var("LOG_MESSAGE_METADATA")
                .unwrap_or_else(|_| "false".to_string())
                .parse()
                .unwrap_or(false),
            enable_user_identifiers: std::env::var("LOG_USER_IDENTIFIERS")
                .unwrap_or_else(|_| "false".to_string())
                .parse()
                .unwrap_or(false),
            hash_salt: {
                let salt = std::env::var("LOG_HASH_SALT")
                    .unwrap_or_else(|_| "default-salt-please-change".to_string());
                if salt.is_empty() || salt == "default-salt-please-change" {
                    anyhow::bail!("LOG_HASH_SALT must be set to a unique, secret value");
                }
                salt
            },
        })
    }
}
