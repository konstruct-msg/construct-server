use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum CryptoSuite {
    #[default]
    ClassicX25519 = 0x01,
    /// A capability label stored as `"0x10"` in `users.crypto_suites` / `devices.crypto_suites`.
    /// It is not the byte Kyber prekeys are signed under — that is `0x11` since PQXDH v2
    /// (`construct_crypto::pqc::KYBER_PREKEY_SIGN_SUITE_V2`) — and it is not renumbered with it:
    /// the value is persisted and sent by clients at registration, and nothing verifies against it.
    HybridKyber1024X25519 = 0x10,
}

impl CryptoSuite {
    pub fn as_hex(&self) -> String {
        format!("0x{:02X}", *self as u8)
    }
    pub fn from_hex(s: &str) -> Option<Self> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        match u8::from_str_radix(s, 16).ok()? {
            0x01 => Some(Self::ClassicX25519),
            0x10 => Some(Self::HybridKyber1024X25519),
            _ => None,
        }
    }
    pub fn is_post_quantum(&self) -> bool {
        matches!(self, Self::HybridKyber1024X25519)
    }
}

impl Serialize for CryptoSuite {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        s.serialize_str(&self.as_hex())
    }
}

impl<'de> Deserialize<'de> for CryptoSuite {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(d)?;
        Self::from_hex(&s).ok_or_else(|| serde::de::Error::custom("Invalid suite"))
    }
}
