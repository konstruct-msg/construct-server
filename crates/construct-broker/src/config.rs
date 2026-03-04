use anyhow::Result;
use construct_config::KafkaConfig;
use rdkafka::config::ClientConfig;
use tracing::info;

/// Creates a new `rdkafka::config::ClientConfig` from the application's `KafkaConfig`.
///
/// This function centralizes the logic for creating a Kafka client configuration,
/// ensuring that both producers and consumers are configured consistently.
///
/// It handles:
/// - Setting up bootstrap servers.
/// - Enabling SSL/TLS if `ssl_enabled` is true.
/// - Configuring SASL PLAIN authentication if a username and password are provided.
///
/// # Arguments
/// * `config` - A reference to the `KafkaConfig` struct containing the Kafka connection details.
///
/// # Returns
/// * A `Result` containing the configured `ClientConfig` or an error if configuration fails.
pub fn create_client_config(config: &KafkaConfig) -> Result<ClientConfig> {
    if !config.enabled {
        // Return a minimal config for a disabled client.
        // This is used for creating placeholder clients that won't be used.
        let mut client_config = ClientConfig::new();
        client_config.set("bootstrap.servers", &config.brokers);
        return Ok(client_config);
    }

    let mut client_config = ClientConfig::new();
    client_config.set("bootstrap.servers", &config.brokers);

    if config.ssl_enabled {
        info!("Enabling SSL/TLS for Kafka connection");

        // Configure CA certificate for self-signed certs
        if let Some(ca_location) = &config.ssl_ca_location {
            info!(ca_location = %ca_location, "Configuring custom CA certificate");
            client_config.set("ssl.ca.location", ca_location);
        }
    }

    // Configure SASL if a mechanism is provided
    if let (Some(mechanism), Some(username), Some(password)) = (
        &config.sasl_mechanism,
        &config.sasl_username,
        &config.sasl_password,
    ) {
        info!(sasl_mechanism = %mechanism, "Configuring SASL authentication");
        client_config
            .set("sasl.mechanism", mechanism)
            .set("sasl.username", username)
            .set("sasl.password", password);

        if config.ssl_enabled {
            client_config.set("security.protocol", "sasl_ssl");
        } else {
            client_config.set("security.protocol", "sasl_plaintext"); // SASL без SSL
        }
    } else if config.ssl_enabled {
        client_config.set("security.protocol", "ssl"); // Только SSL, без SASL
    } else {
        client_config.set("security.protocol", "plaintext"); // Без SSL и SASL
    }

    Ok(client_config)
}
