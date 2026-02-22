// ============================================================================
// Kafka Configuration
// ============================================================================
// Phase 2.8: Extracted from config.rs for better organization

/// Kafka configuration for reliable message delivery
#[derive(Clone, Debug)]
pub struct KafkaConfig {
    /// Whether Kafka is enabled (false = Redis-only mode for testing/rollback)
    pub enabled: bool,
    /// Comma-separated list of Kafka brokers (e.g., "kafka1:9092,kafka2:9092")
    pub brokers: String,
    /// Kafka topic name for messages
    pub topic: String,
    /// Consumer group ID for delivery workers
    pub consumer_group: String,
    /// SSL/TLS enabled
    pub ssl_enabled: bool,
    /// SASL mechanism (e.g., "SCRAM-SHA-256", "PLAIN")
    pub sasl_mechanism: Option<String>,
    /// SASL username
    pub sasl_username: Option<String>,
    /// SASL password
    pub sasl_password: Option<String>,
    /// Path to CA certificate file (for self-signed certificates)
    pub ssl_ca_location: Option<String>,
    // producer-specific settings
    pub producer_compression: String, // "zstd" | "snappy" | "gzip" | "lz4" | "none"
    pub producer_acks: String,        // "all" | "1" | "-1" | "0"
    pub producer_linger_ms: u32,
    pub producer_batch_size: u32,
    pub producer_max_in_flight: u32,
    pub producer_retries: u32,
    pub producer_request_timeout_ms: u32,
    pub producer_delivery_timeout_ms: u32,
    pub producer_enable_idempotence: bool,
}

impl KafkaConfig {
    pub(crate) fn from_env() -> Self {
        Self {
            enabled: std::env::var("KAFKA_ENABLED")
                .unwrap_or_else(|_| "false".to_string())
                .parse()
                .unwrap_or(false),
            brokers: std::env::var("KAFKA_BROKERS")
                .unwrap_or_else(|_| "localhost:9092".to_string()),
            topic: std::env::var("KAFKA_TOPIC")
                .unwrap_or_else(|_| "construct-messages".to_string()),
            consumer_group: std::env::var("KAFKA_CONSUMER_GROUP")
                .unwrap_or_else(|_| "construct-delivery-workers".to_string()),
            ssl_enabled: std::env::var("KAFKA_SSL_ENABLED")
                .unwrap_or_else(|_| "false".to_string())
                .parse()
                .unwrap_or(false),
            sasl_mechanism: std::env::var("KAFKA_SASL_MECHANISM").ok(),
            sasl_username: std::env::var("KAFKA_SASL_USERNAME").ok(),
            sasl_password: std::env::var("KAFKA_SASL_PASSWORD").ok(),
            ssl_ca_location: std::env::var("KAFKA_SSL_CA_LOCATION").ok(),
            // producer-specific settings
            producer_compression: std::env::var("KAFKA_PRODUCER_COMPRESSION")
                .unwrap_or_else(|_| "snappy".to_string()),
            producer_acks: std::env::var("KAFKA_PRODUCER_ACKS")
                .unwrap_or_else(|_| "all".to_string()),
            producer_linger_ms: std::env::var("KAFKA_PRODUCER_LINGER_MS")
                .unwrap_or_else(|_| "10".to_string())
                .parse()
                .unwrap_or(10),
            producer_batch_size: std::env::var("KAFKA_PRODUCER_BATCH_SIZE")
                .unwrap_or_else(|_| "16384".to_string())
                .parse()
                .unwrap_or(16384),
            producer_max_in_flight: std::env::var("KAFKA_PRODUCER_MAX_IN_FLIGHT")
                .unwrap_or_else(|_| "5".to_string())
                .parse()
                .unwrap_or(5),
            producer_retries: std::env::var("KAFKA_PRODUCER_RETRIES")
                .unwrap_or_else(|_| "2147483647".to_string())
                .parse()
                .unwrap_or(2147483647),
            producer_request_timeout_ms: std::env::var("KAFKA_PRODUCER_REQUEST_TIMEOUT_MS")
                .unwrap_or_else(|_| "30000".to_string())
                .parse()
                .unwrap_or(30000),
            producer_delivery_timeout_ms: std::env::var("KAFKA_PRODUCER_DELIVERY_TIMEOUT_MS")
                .unwrap_or_else(|_| "120000".to_string())
                .parse()
                .unwrap_or(120000),
            producer_enable_idempotence: std::env::var("KAFKA_PRODUCER_ENABLE_IDEMPOTENCE")
                .unwrap_or_else(|_| "true".to_string())
                .parse()
                .unwrap_or(true),
        }
    }
}
