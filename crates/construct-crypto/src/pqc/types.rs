// ============================================================================
// Post-Quantum Cryptography Types
// ============================================================================
//
// Type definitions for hybrid post-quantum cryptography.
// These types are used for key bundles, signatures, and KEM operations.
//
// ============================================================================

use serde::{Deserialize, Serialize};

/// Hybrid KEM (Key Encapsulation Mechanism) public key
/// Combines classical X25519 with post-quantum ML-KEM-768
///
/// Format: classical_key (32 bytes) || pq_key (1184 bytes for ML-KEM-768)
/// Total size: 1216 bytes
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HybridKemPublicKey {
    /// Classical X25519 public key (32 bytes)
    #[serde(with = "serde_bytes")]
    pub classical: Vec<u8>, // X25519: 32 bytes

    /// Post-quantum ML-KEM-768 public key (1184 bytes)
    #[serde(with = "serde_bytes")]
    pub pq: Vec<u8>, // ML-KEM-768: 1184 bytes

    /// Key version for rotation support
    pub version: u8,
}

impl HybridKemPublicKey {
    /// Serialize hybrid KEM public key to wire format
    ///
    /// Format: version (1 byte) || classical_len (2 bytes) || classical || pq_len (2 bytes) || pq
    pub fn to_wire_format(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(1 + 2 + self.classical.len() + 2 + self.pq.len());
        result.push(self.version);
        result.extend_from_slice(&(self.classical.len() as u16).to_be_bytes());
        result.extend_from_slice(&self.classical);
        result.extend_from_slice(&(self.pq.len() as u16).to_be_bytes());
        result.extend_from_slice(&self.pq);
        result
    }

    /// Deserialize hybrid KEM public key from wire format
    pub fn from_wire_format(data: &[u8]) -> std::result::Result<Self, String> {
        if data.len() < 1 + 2 + 2 {
            return Err("Wire format too short".to_string());
        }

        let version = data[0];
        let classical_len = u16::from_be_bytes([data[1], data[2]]) as usize;

        if data.len() < 1 + 2 + classical_len + 2 {
            return Err("Wire format too short for classical key".to_string());
        }

        let classical = data[3..3 + classical_len].to_vec();

        let pq_start = 3 + classical_len;
        let pq_len = u16::from_be_bytes([data[pq_start], data[pq_start + 1]]) as usize;

        if data.len() < pq_start + 2 + pq_len {
            return Err("Wire format too short for PQ key".to_string());
        }

        let pq = data[pq_start + 2..pq_start + 2 + pq_len].to_vec();

        Ok(Self {
            classical,
            pq,
            version,
        })
    }

    /// Get total size of the hybrid public key
    pub fn size(&self) -> usize {
        self.classical.len() + self.pq.len()
    }
}

/// Hybrid signature public key (for identity keys)
/// Combines classical Ed25519 with post-quantum ML-DSA-65
///
/// Format: classical_key (32 bytes) || pq_key (1952 bytes for ML-DSA-65)
/// Total size: 1984 bytes
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HybridSignaturePublicKey {
    /// Classical Ed25519 public key (32 bytes)
    #[serde(with = "serde_bytes")]
    pub classical: Vec<u8>, // Ed25519: 32 bytes

    /// Post-quantum ML-DSA-65 public key (1952 bytes)
    #[serde(with = "serde_bytes")]
    pub pq: Vec<u8>, // ML-DSA-65: 1952 bytes

    /// Key version for rotation support
    pub version: u8,
}

impl HybridSignaturePublicKey {
    /// Serialize hybrid signature public key to wire format
    ///
    /// Format: version (1 byte) || classical_len (2 bytes) || classical || pq_len (2 bytes) || pq
    pub fn to_wire_format(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(1 + 2 + self.classical.len() + 2 + self.pq.len());
        result.push(self.version);
        result.extend_from_slice(&(self.classical.len() as u16).to_be_bytes());
        result.extend_from_slice(&self.classical);
        result.extend_from_slice(&(self.pq.len() as u16).to_be_bytes());
        result.extend_from_slice(&self.pq);
        result
    }

    /// Deserialize hybrid signature public key from wire format
    pub fn from_wire_format(data: &[u8]) -> std::result::Result<Self, String> {
        if data.len() < 1 + 2 + 2 {
            return Err("Wire format too short".to_string());
        }

        let version = data[0];
        let classical_len = u16::from_be_bytes([data[1], data[2]]) as usize;

        if data.len() < 1 + 2 + classical_len + 2 {
            return Err("Wire format too short for classical key".to_string());
        }

        let classical = data[3..3 + classical_len].to_vec();

        let pq_start = 3 + classical_len;
        let pq_len = u16::from_be_bytes([data[pq_start], data[pq_start + 1]]) as usize;

        if data.len() < pq_start + 2 + pq_len {
            return Err("Wire format too short for PQ key".to_string());
        }

        let pq = data[pq_start + 2..pq_start + 2 + pq_len].to_vec();

        Ok(Self {
            classical,
            pq,
            version,
        })
    }

    /// Get total size of the hybrid signature public key
    pub fn size(&self) -> usize {
        self.classical.len() + self.pq.len()
    }
}

/// Hybrid signature
/// Combines classical Ed25519 signature with post-quantum ML-DSA-65 signature
///
/// Format: classical_sig (64 bytes) || pq_sig (3293 bytes for ML-DSA-65)
/// Total size: 3357 bytes
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HybridSignature {
    /// Classical Ed25519 signature (64 bytes)
    #[serde(with = "serde_bytes")]
    pub classical: Vec<u8>, // Ed25519: 64 bytes

    /// Post-quantum ML-DSA-65 signature (3293 bytes)
    #[serde(with = "serde_bytes")]
    pub pq: Vec<u8>, // ML-DSA-65: 3293 bytes
}

impl HybridSignature {
    /// Serialize hybrid signature to wire format
    ///
    /// Format: classical_len (2 bytes) || classical || pq_len (2 bytes) || pq
    pub fn to_wire_format(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(2 + self.classical.len() + 2 + self.pq.len());
        result.extend_from_slice(&(self.classical.len() as u16).to_be_bytes());
        result.extend_from_slice(&self.classical);
        result.extend_from_slice(&(self.pq.len() as u16).to_be_bytes());
        result.extend_from_slice(&self.pq);
        result
    }

    /// Deserialize hybrid signature from wire format
    pub fn from_wire_format(data: &[u8]) -> std::result::Result<Self, String> {
        if data.len() < 2 + 2 {
            return Err("Wire format too short".to_string());
        }

        let classical_len = u16::from_be_bytes([data[0], data[1]]) as usize;

        if data.len() < 2 + classical_len + 2 {
            return Err("Wire format too short for classical signature".to_string());
        }

        let classical = data[2..2 + classical_len].to_vec();

        let pq_start = 2 + classical_len;
        let pq_len = u16::from_be_bytes([data[pq_start], data[pq_start + 1]]) as usize;

        if data.len() < pq_start + 2 + pq_len {
            return Err("Wire format too short for PQ signature".to_string());
        }

        let pq = data[pq_start + 2..pq_start + 2 + pq_len].to_vec();

        Ok(Self { classical, pq })
    }

    /// Get total size of the hybrid signature
    pub fn size(&self) -> usize {
        self.classical.len() + self.pq.len()
    }
}

/// Expected sizes for hybrid keys (for validation)
pub mod key_sizes {
    /// X25519 public key size
    pub const X25519_PUBLIC_KEY: usize = 32;

    /// ML-KEM-768 public key size (FIPS 203)
    pub const ML_KEM_768_PUBLIC_KEY: usize = 1184;

    /// ML-KEM-768 ciphertext size
    pub const ML_KEM_768_CIPHERTEXT: usize = 1088;

    /// Hybrid KEM public key total size
    pub const HYBRID_KEM_PUBLIC_KEY: usize = X25519_PUBLIC_KEY + ML_KEM_768_PUBLIC_KEY; // 1216 bytes

    /// Ed25519 public key size
    pub const ED25519_PUBLIC_KEY: usize = 32;

    /// Ed25519 signature size
    pub const ED25519_SIGNATURE: usize = 64;

    /// ML-DSA-65 public key size (FIPS 204)
    pub const ML_DSA_65_PUBLIC_KEY: usize = 1952;

    /// ML-DSA-65 signature size
    pub const ML_DSA_65_SIGNATURE: usize = 3293;

    /// Hybrid signature public key total size
    pub const HYBRID_SIGNATURE_PUBLIC_KEY: usize = ED25519_PUBLIC_KEY + ML_DSA_65_PUBLIC_KEY; // 1984 bytes

    /// Hybrid signature total size
    pub const HYBRID_SIGNATURE: usize = ED25519_SIGNATURE + ML_DSA_65_SIGNATURE;
    // 3357 bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_kem_public_key_wire_format() {
        let key = HybridKemPublicKey {
            classical: vec![0u8; 32],
            pq: vec![0u8; 1184],
            version: 1,
        };

        let wire = key.to_wire_format();
        let reconstructed = HybridKemPublicKey::from_wire_format(&wire).unwrap();

        assert_eq!(key.version, reconstructed.version);
        assert_eq!(key.classical, reconstructed.classical);
        assert_eq!(key.pq, reconstructed.pq);
    }

    #[test]
    fn test_hybrid_signature_wire_format() {
        let sig = HybridSignature {
            classical: vec![0u8; 64],
            pq: vec![0u8; 3293],
        };

        let wire = sig.to_wire_format();
        let reconstructed = HybridSignature::from_wire_format(&wire).unwrap();

        assert_eq!(sig.classical, reconstructed.classical);
        assert_eq!(sig.pq, reconstructed.pq);
    }

    #[test]
    fn test_key_sizes() {
        assert_eq!(key_sizes::HYBRID_KEM_PUBLIC_KEY, 1216);
        assert_eq!(key_sizes::HYBRID_SIGNATURE_PUBLIC_KEY, 1984);
        assert_eq!(key_sizes::HYBRID_SIGNATURE, 3357);
    }
}
