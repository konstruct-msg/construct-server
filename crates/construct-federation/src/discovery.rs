// ============================================================================
// Federation Discovery - Find remote instance endpoints
// ============================================================================

use anyhow::Result;
use serde::Deserialize;

/// Federation instance information from .well-known/konstruct
#[derive(Debug, Clone, Deserialize)]
pub struct FederationInfo {
    pub server: String,
    pub version: String,
    pub federation: FederationConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FederationConfig {
    pub enabled: bool,
    pub protocol_version: String,
    pub endpoints: FederationEndpoints,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FederationEndpoints {
    pub messages: String,
    pub health: String,
}

/// Discover federation info for a domain
pub async fn discover_instance(domain: &str) -> Result<FederationInfo> {
    let well_known_url = format!("https://{}/.well-known/konstruct", domain);

    tracing::debug!(domain = %domain, url = %well_known_url, "Discovering federation instance");

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    let response = client.get(&well_known_url).send().await?;

    if !response.status().is_success() {
        anyhow::bail!(
            "Federation discovery failed for {}: HTTP {}",
            domain,
            response.status()
        );
    }

    let info: FederationInfo = response.json().await?;

    if !info.federation.enabled {
        anyhow::bail!("Federation is disabled on {}", domain);
    }

    tracing::info!(
        domain = %domain,
        server = %info.server,
        version = %info.version,
        "Successfully discovered federation instance"
    );

    Ok(info)
}
