//! VeilService business logic — issue (sign) veil-front capabilities.
//!
//! ⚠️ Wire-format coupling: the signing message and the capability blob layout MUST
//! match `construct-veil-protocol::capability` exactly (the relay verifies offline
//! against these bytes). They are replicated here because construct-server and
//! construct-veil are separate repos. Keep the two in sync:
//!   signing msg = "veil-cap-v1" || ticket_id[16] || auth_key[32]
//!                 || not_before[8 LE] || not_after[8 LE] || suite_id[1] || scope_utf8
//!   blob        = ticket_id[16] || auth_key[32] || not_before[8 LE] || not_after[8 LE]
//!                 || suite_id[1] || scope_len[u8] || scope || sig[64]

use std::collections::HashMap;
use std::sync::Arc;

use construct_server_shared::db::DbPool;
use ed25519_dalek::{Signer, SigningKey};
use uuid::Uuid;

/// Default capability validity: 60 days (aligned with Let's Encrypt rotation).
pub const DEFAULT_TICKET_TTL_SECS: i64 = 60 * 24 * 3600;

/// Domain-separation prefix for the capability signing message. MUST match
/// `construct_veil_protocol::capability::CAP_DOMAIN`.
const CAP_DOMAIN: &[u8] = b"veil-cap-v1";

const SUITE_CLASSIC_V1: u8 = 1;

/// Network parameters for one relay, resolved from config.
#[derive(Clone)]
pub struct RelayInfo {
    /// Relay scope id (matches the relay's --relay-scope; "" = any).
    pub scope: String,
    /// hex SHA-256 SPKI pin of the relay's veil-front cert.
    pub spki: String,
    /// TLS SNI / cert hostname.
    pub sni: String,
}

/// Shared service context.
pub struct VeilServiceContext {
    pub db_pool: Arc<DbPool>,
    /// relay_address (host:port) → RelayInfo.
    pub relays: HashMap<String, RelayInfo>,
    /// Issuer Ed25519 signing key (32-byte seed). SECRET.
    pub issuer: SigningKey,
    /// Capability validity in seconds.
    pub ticket_ttl_secs: i64,
}

#[derive(thiserror::Error, Debug)]
pub enum IssueError {
    #[error("unknown relay: {0}")]
    UnknownRelay(String),
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
}

/// Result of issuing a capability.
pub struct IssuedCapability {
    /// Canonical signed capability blob (client feeds to veil_start).
    pub blob: Vec<u8>,
    pub relay_address: String,
    pub spki: String,
    pub sni: String,
    pub not_after: i64,
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn random_bytes(n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    getrandom::getrandom(&mut b).expect("OS CSPRNG unavailable");
    b
}

/// Build the domain-separated message the issuer signs (matches the protocol crate).
fn signing_message(
    ticket_id: &[u8],
    auth_key: &[u8],
    not_before: i64,
    not_after: i64,
    suite_id: u8,
    scope: &str,
) -> Vec<u8> {
    let mut m = Vec::with_capacity(CAP_DOMAIN.len() + 66 + scope.len());
    m.extend_from_slice(CAP_DOMAIN);
    m.extend_from_slice(ticket_id);
    m.extend_from_slice(auth_key);
    m.extend_from_slice(&(not_before as u64).to_le_bytes());
    m.extend_from_slice(&(not_after as u64).to_le_bytes());
    m.push(suite_id);
    m.extend_from_slice(scope.as_bytes());
    m
}

/// Encode the canonical capability blob (matches the protocol crate).
fn encode_capability(
    ticket_id: &[u8],
    auth_key: &[u8],
    not_before: i64,
    not_after: i64,
    suite_id: u8,
    scope: &str,
    sig: &[u8; 64],
) -> Vec<u8> {
    let scope_bytes = scope.as_bytes();
    let mut out = Vec::with_capacity(66 + scope_bytes.len() + 64);
    out.extend_from_slice(ticket_id); // 16
    out.extend_from_slice(auth_key); // 32
    out.extend_from_slice(&(not_before as u64).to_le_bytes()); // 8
    out.extend_from_slice(&(not_after as u64).to_le_bytes()); // 8
    out.push(suite_id); // 1
    out.push(scope_bytes.len() as u8); // 1
    out.extend_from_slice(scope_bytes);
    out.extend_from_slice(sig); // 64
    out
}

/// Issue (generate + sign + persist) a fresh capability for `user_id` on `relay_address`.
pub async fn issue_capability(
    ctx: &VeilServiceContext,
    user_id: Uuid,
    relay_address: &str,
) -> Result<IssuedCapability, IssueError> {
    let relay = ctx
        .relays
        .get(relay_address)
        .ok_or_else(|| IssueError::UnknownRelay(relay_address.to_string()))?;

    let now = unix_now();
    let not_before = now;
    let not_after = now + ctx.ticket_ttl_secs;
    let ticket_id = random_bytes(16);
    let auth_key = random_bytes(32);
    let suite_id = SUITE_CLASSIC_V1;

    let msg = signing_message(
        &ticket_id,
        &auth_key,
        not_before,
        not_after,
        suite_id,
        &relay.scope,
    );
    let sig: [u8; 64] = ctx.issuer.sign(&msg).to_bytes();

    let blob = encode_capability(
        &ticket_id,
        &auth_key,
        not_before,
        not_after,
        suite_id,
        &relay.scope,
        &sig,
    );

    sqlx::query(
        "INSERT INTO veil_tickets \
         (ticket_id, auth_key, user_id, relay_scope, not_before, not_after, suite_id) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(&ticket_id)
    .bind(&auth_key)
    .bind(user_id)
    .bind(&relay.scope)
    .bind(not_before)
    .bind(not_after)
    .bind(suite_id as i16)
    .execute(&*ctx.db_pool)
    .await?;

    Ok(IssuedCapability {
        blob,
        relay_address: relay_address.to_string(),
        spki: relay.spki.clone(),
        sni: relay.sni.clone(),
        not_after,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_layout_is_canonical_length() {
        // 16 + 32 + 8 + 8 + 1 + 1 + scope + 64
        let sig = [0u8; 64];
        let blob = encode_capability(&[1; 16], &[2; 32], 0, 100, 1, "ru", &sig);
        assert_eq!(blob.len(), 66 + 2 + 64);
        // scope length byte is at offset 65, scope bytes follow.
        assert_eq!(blob[65], 2);
        assert_eq!(&blob[66..68], b"ru");
    }

    #[test]
    fn signing_message_is_domain_separated() {
        let m = signing_message(&[1; 16], &[2; 32], 0, 100, 1, "ru");
        assert!(m.starts_with(b"veil-cap-v1"));
        // domain(11) + ticket_id(16) + auth_key(32) + nb(8) + na(8) + suite(1) + scope(2)
        // NOTE: no scope_len byte here (that's only in the blob encoding).
        assert_eq!(m.len(), 11 + 65 + 2);
    }

    /// Cross-repo interop anchor: the backend-produced blob MUST be byte-identical to
    /// construct-veil-protocol's `capability::golden` vector (same fixed inputs). If
    /// this fails, the relay would reject backend-issued capabilities on-device.
    #[test]
    fn backend_blob_matches_protocol_golden() {
        const GOLDEN: &str = "0101010101010101010101010101010102020202020202020202020202020202020202020202020202020202020202020000000000000000640000000000000001027275e00cdb9124a3225a53aa46712bcdee0aab51b01c58f674b1b8d13898bd7dc33dec404cf0e035472ab64689a0163d4f68375b2546ccd83eb8536ecb5daea8130e";
        let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let ticket_id = [1u8; 16];
        let auth_key = [2u8; 32];
        let msg = signing_message(&ticket_id, &auth_key, 0, 100, 1, "ru");
        let sig: [u8; 64] = sk.sign(&msg).to_bytes();
        let blob = encode_capability(&ticket_id, &auth_key, 0, 100, 1, "ru", &sig);
        assert_eq!(hex::encode(&blob), GOLDEN);
    }
}
