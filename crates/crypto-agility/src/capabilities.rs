use crate::{CryptoSuite, ProtocolVersion};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserCapabilities {
    pub user_id: Uuid,
    pub protocol_version: ProtocolVersion,
    pub crypto_suites: Vec<CryptoSuite>,
}

impl UserCapabilities {
    pub fn new(user_id: Uuid, protocol_version: ProtocolVersion) -> Self {
        let crypto_suites = match protocol_version {
            ProtocolVersion::V1Classic => vec![CryptoSuite::ClassicX25519],
            ProtocolVersion::V2HybridPQ => vec![
                CryptoSuite::HybridKyber1024X25519,
                CryptoSuite::ClassicX25519,
            ],
        };
        Self {
            user_id,
            protocol_version,
            crypto_suites,
        }
    }

    pub fn supports_suite(&self, suite: &CryptoSuite) -> bool {
        self.crypto_suites.contains(suite)
    }

    pub fn find_common_suite(&self, other: &Self) -> Option<CryptoSuite> {
        self.crypto_suites
            .iter()
            .find(|&s| other.supports_suite(s))
            .copied()
    }
}

impl Default for UserCapabilities {
    fn default() -> Self {
        Self {
            user_id: Uuid::nil(),
            protocol_version: ProtocolVersion::default(),
            crypto_suites: vec![CryptoSuite::default()],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PQPrekeys {
    pub user_id: Uuid,
    pub pq_identity_key: Vec<u8>,
    pub pq_kem_key: Vec<u8>,
    pub pq_signature: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}
