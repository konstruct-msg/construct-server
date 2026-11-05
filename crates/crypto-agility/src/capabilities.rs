use crate::{CryptoSuite, ProtocolVersion};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserCapabilities {
    pub user_id: Uuid,
    pub protocol_version: ProtocolVersion,
    pub crypto_suites: Vec<CryptoSuite>,
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
