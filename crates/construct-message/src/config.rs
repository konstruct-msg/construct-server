// Only compiled when the "kafka" feature is enabled.
#[cfg(feature = "kafka")]
use anyhow::Result;
#[cfg(feature = "kafka")]
use construct_config::KafkaConfig;
#[cfg(feature = "kafka")]
use rdkafka::config::ClientConfig;
#[cfg(feature = "kafka")]
use tracing::info;

/// Creates a new `rdkafka::config::ClientConfig` from the application's `KafkaConfig`.
#[cfg(feature = "kafka")]
pub fn create_client_config(config: &KafkaConfig) -> Result<ClientConfig> {
    if !config.enabled {
        let mut client_config = ClientConfig::new();
        client_config.set("bootstrap.servers", &config.brokers);
        return Ok(client_config);
    }

    let mut client_config = ClientConfig::new();
    client_config.set("bootstrap.servers", &config.brokers);

    if config.ssl_enabled {
        info!("Enabling SSL/TLS for Kafka connection");
        if let Some(ca_location) = &config.ssl_ca_location {
            info!(ca_location = %ca_location, "Configuring custom CA certificate");
            client_config.set("ssl.ca.location", ca_location);
        }
    }

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
            client_config.set("security.protocol", "sasl_plaintext");
        }
    } else if config.ssl_enabled {
        client_config.set("security.protocol", "ssl");
    } else {
        client_config.set("security.protocol", "plaintext");
    }

    Ok(client_config)
}
