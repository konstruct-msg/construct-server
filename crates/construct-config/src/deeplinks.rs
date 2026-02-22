// ============================================================================
// Deep Links Configuration
// ============================================================================
// Phase 2.8: Extracted from config.rs for better organization

/// Deep links configuration for Universal Links (iOS) and App Links (Android)
#[derive(Clone, Debug)]
pub struct DeepLinksConfig {
    /// Apple Team ID for Universal Links
    pub apple_team_id: String,
    /// Android package name (e.g., "com.konstruct.messenger")
    pub android_package_name: String,
    /// Android certificate SHA-256 fingerprint for App Links verification
    pub android_cert_fingerprint: String,
}

impl DeepLinksConfig {
    pub(crate) fn from_env() -> Self {
        Self {
            apple_team_id: std::env::var("APPLE_TEAM_ID").unwrap_or_else(|_| String::new()),
            android_package_name: std::env::var("ANDROID_PACKAGE_NAME")
                .unwrap_or_else(|_| "com.konstruct.messenger".to_string()),
            android_cert_fingerprint: std::env::var("ANDROID_CERT_FINGERPRINT")
                .unwrap_or_else(|_| String::new()),
        }
    }
}
