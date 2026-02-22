use crate::{CryptoSuite, ProtocolVersion, UserCapabilities};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiatedCapabilities {
    pub protocol_version: ProtocolVersion,
    pub crypto_suites: Vec<CryptoSuite>,
}

impl NegotiatedCapabilities {
    pub fn best_suite(&self) -> CryptoSuite {
        self.crypto_suites.first().copied().unwrap_or_default()
    }
}

pub fn negotiate_protocol(
    a: &UserCapabilities,
    b: &UserCapabilities,
) -> Option<NegotiatedCapabilities> {
    let protocol_version = match (a.protocol_version, b.protocol_version) {
        (ProtocolVersion::V1Classic, _) | (_, ProtocolVersion::V1Classic) => {
            ProtocolVersion::V1Classic
        }
        (ProtocolVersion::V2HybridPQ, ProtocolVersion::V2HybridPQ) => ProtocolVersion::V2HybridPQ,
    };

    let common: Vec<_> = a
        .crypto_suites
        .iter()
        .filter(|&s| b.supports_suite(s))
        .copied()
        .collect();
    if common.is_empty() {
        return None;
    }

    Some(NegotiatedCapabilities {
        protocol_version,
        crypto_suites: common,
    })
}
