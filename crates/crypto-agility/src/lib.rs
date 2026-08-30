//! Construct Crypto-Agility - Protocol version negotiation and crypto suite management

mod capabilities;
mod error;
mod invites;
mod negotiation;
mod protocol;
mod suites;

pub use capabilities::UserCapabilities;
pub use error::{CryptoAgilityError, Result};
pub use invites::{
    INVITE_BURN_RETENTION_SECONDS, INVITE_TTL_MIN_SECONDS, INVITE_TTL_SECONDS, InviteToken,
    InviteTokenRecord, InviteValidationError,
};
pub use negotiation::{NegotiatedCapabilities, negotiate_protocol};
pub use protocol::ProtocolVersion;
pub use suites::CryptoSuite;

pub use chrono::{DateTime, Utc};
pub use uuid::Uuid;
