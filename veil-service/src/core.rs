//! VeilService business logic — issue (sign) veil-front capabilities.
//!
//! Wire-format coupling: the signing message and the capability blob layout MUST
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

/// EntryDirectory v1: default number of pre-issued **alternate** fronts (K) returned
/// alongside the primary capability. See `decisions/entry-directory-design.md` Source 1.
pub const DEFAULT_ALTERNATES_K: usize = 3;

/// Rotation epoch for alternate-front selection (24h). The K fronts a given user sees
/// are stable within an epoch and rotate across epochs — Salmon-lite: each account
/// learns a bounded, rotating subset, which bounds (does not prevent) enumeration.
pub const ALT_ROTATION_SECS: i64 = 24 * 3600;

/// Domain-separation prefix for the capability signing message. MUST match
/// `construct_veil_protocol::capability::CAP_DOMAIN`.
const CAP_DOMAIN: &[u8] = b"veil-cap-v1";

/// Domain-separation prefix for the key-bound (B1) capability signing message.
/// MUST match `construct_veil_protocol::capability::CAP_V2_DOMAIN`.
const CAP_V2_DOMAIN: &[u8] = b"veil-cap-v2";

/// `role` value: end-user client. MUST match `construct_veil_protocol::capability::ROLE_USER`.
pub const ROLE_USER: u8 = 0;

/// `role` value: chaining relay. MUST match `construct_veil_protocol::capability::ROLE_RELAY`.
pub const ROLE_RELAY: u8 = 1;

const SUITE_CLASSIC_V1: u8 = 1;

/// Length of a veil access keypair's public key in bytes (Ed25519).
const VEIL_PK_LEN: usize = 32;

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
    #[error("veil_pk must be exactly {VEIL_PK_LEN} bytes, got {0}")]
    InvalidVeilPk(usize),
    #[error("unknown role: {0}")]
    InvalidRole(u32),
    /// `relay_address` was empty and no relays are configured at all.
    #[error("no relays configured")]
    NoRelaysConfigured,
    /// `relay_address` was empty but more than one relay is configured — the client
    /// must name the primary (auto first-issue still always sends the seed address).
    #[error("relay_address required when multiple relays are configured")]
    RelayAddressRequired,
}

/// Result of issuing a capability.
pub struct IssuedCapability {
    /// Canonical signed capability blob (client feeds to veil_start).
    pub blob: Vec<u8>,
    pub relay_address: String,
    pub spki: String,
    pub sni: String,
    pub not_after: i64,
    /// 1 = B2 bearer capability (AUTH v2), 2 = B1 key-bound capability (AUTH v3).
    pub capability_version: u32,
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

/// Parse `VEIL_RELAYS` multi-front records: `address,scope,spki,sni` separated by `;`.
/// Malformed records are skipped (and counted in the return's second field).
/// Whitespace around fields is trimmed; blank records are ignored.
pub fn parse_relays_spec(spec: &str) -> (HashMap<String, RelayInfo>, usize) {
    let mut relays = HashMap::new();
    let mut skipped = 0usize;
    for record in spec.split(';') {
        let record = record.trim();
        if record.is_empty() {
            continue;
        }
        let f: Vec<&str> = record.split(',').map(|s| s.trim()).collect();
        match f.as_slice() {
            [addr, scope, spki, sni] if !addr.is_empty() => {
                relays.insert(
                    addr.to_string(),
                    RelayInfo {
                        scope: scope.to_string(),
                        spki: spki.to_string(),
                        sni: sni.to_string(),
                    },
                );
            }
            _ => skipped += 1,
        }
    }
    (relays, skipped)
}

/// Insert the legacy single-relay env vars if `address` is non-empty and not already set.
pub fn merge_legacy_relay(
    relays: &mut HashMap<String, RelayInfo>,
    address: &str,
    scope: &str,
    spki: &str,
    sni: &str,
) {
    if address.is_empty() {
        return;
    }
    relays
        .entry(address.to_string())
        .or_insert_with(|| RelayInfo {
            scope: scope.to_string(),
            spki: spki.to_string(),
            sni: sni.to_string(),
        });
}

/// Resolve the primary relay address for an IssueVeilCapability call.
///
/// Empty `requested` is accepted when exactly one relay is configured (handy for
/// auto first-issue clients that only know "the" front). With N>1 the client must
/// name the primary so Salmon-lite alternate selection has a well-defined exclude set.
pub fn resolve_primary_relay<'a>(
    relays: &'a HashMap<String, RelayInfo>,
    requested: &str,
) -> Result<&'a str, IssueError> {
    let requested = requested.trim();
    if !requested.is_empty() {
        return relays
            .get_key_value(requested)
            .map(|(k, _)| k.as_str())
            .ok_or_else(|| IssueError::UnknownRelay(requested.to_string()));
    }
    match relays.len() {
        0 => Err(IssueError::NoRelaysConfigured),
        1 => Ok(relays.keys().next().map(|s| s.as_str()).expect("len==1")),
        _ => Err(IssueError::RelayAddressRequired),
    }
}

/// Intermediate mint result for a B2 bearer capability (before DB persist).
pub struct MintedB2 {
    pub issued: IssuedCapability,
    pub ticket_id: Vec<u8>,
    pub auth_key: Vec<u8>,
    pub not_before: i64,
    pub suite_id: u8,
    pub relay_scope: String,
}

/// Intermediate mint result for a B1 key-bound capability (before DB persist).
pub struct MintedV2 {
    pub issued: IssuedCapability,
    pub ticket_id: Vec<u8>,
    pub veil_pk: [u8; VEIL_PK_LEN],
    pub role: u8,
    pub not_before: i64,
    pub suite_id: u8,
    pub relay_scope: String,
}

/// Mint (sign) a B2 bearer capability without touching the database.
///
/// Separated from persist so unit tests can exercise the full sign→encode path
/// offline (and so a future batch issuer can mint many before a single flush).
pub fn mint_capability_b2(
    issuer: &SigningKey,
    relay_address: &str,
    relay: &RelayInfo,
    ticket_ttl_secs: i64,
    now: i64,
) -> MintedB2 {
    let not_before = now;
    let not_after = now + ticket_ttl_secs;
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
    let sig: [u8; 64] = issuer.sign(&msg).to_bytes();
    let blob = encode_capability(
        &ticket_id,
        &auth_key,
        not_before,
        not_after,
        suite_id,
        &relay.scope,
        &sig,
    );

    MintedB2 {
        issued: IssuedCapability {
            blob,
            relay_address: relay_address.to_string(),
            spki: relay.spki.clone(),
            sni: relay.sni.clone(),
            not_after,
            capability_version: 1,
        },
        ticket_id,
        auth_key,
        not_before,
        suite_id,
        relay_scope: relay.scope.clone(),
    }
}

/// Mint (sign) a B1 key-bound capability without touching the database.
pub fn mint_capability_v2(
    issuer: &SigningKey,
    relay_address: &str,
    relay: &RelayInfo,
    veil_pk: [u8; VEIL_PK_LEN],
    role: u8,
    ticket_ttl_secs: i64,
    now: i64,
) -> MintedV2 {
    let not_before = now;
    let not_after = now + ticket_ttl_secs;
    let ticket_id = random_bytes(16);
    let suite_id = SUITE_CLASSIC_V1;

    let msg = signing_message_v2(
        &ticket_id,
        &veil_pk,
        role,
        not_before,
        not_after,
        suite_id,
        &relay.scope,
    );
    let sig: [u8; 64] = issuer.sign(&msg).to_bytes();
    let blob = encode_capability_v2(
        &ticket_id,
        &veil_pk,
        role,
        not_before,
        not_after,
        suite_id,
        &relay.scope,
        &sig,
    );

    MintedV2 {
        issued: IssuedCapability {
            blob,
            relay_address: relay_address.to_string(),
            spki: relay.spki.clone(),
            sni: relay.sni.clone(),
            not_after,
            capability_version: 2,
        },
        ticket_id,
        veil_pk,
        role,
        not_before,
        suite_id,
        relay_scope: relay.scope.clone(),
    }
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

/// Build the domain-separated message the issuer signs for a **B1** (key-bound)
/// capability. MUST match `construct_veil_protocol::capability::CapabilityV2::signing_message`.
fn signing_message_v2(
    ticket_id: &[u8],
    veil_pk: &[u8],
    role: u8,
    not_before: i64,
    not_after: i64,
    suite_id: u8,
    scope: &str,
) -> Vec<u8> {
    let mut m = Vec::with_capacity(CAP_V2_DOMAIN.len() + 67 + scope.len());
    m.extend_from_slice(CAP_V2_DOMAIN);
    m.extend_from_slice(ticket_id);
    m.extend_from_slice(veil_pk);
    m.push(role);
    m.extend_from_slice(&(not_before as u64).to_le_bytes());
    m.extend_from_slice(&(not_after as u64).to_le_bytes());
    m.push(suite_id);
    m.extend_from_slice(scope.as_bytes());
    m
}

/// Encode the canonical **B1** capability blob. MUST match
/// `construct_veil_protocol::capability::CapabilityV2::encode`.
#[allow(clippy::too_many_arguments)]
fn encode_capability_v2(
    ticket_id: &[u8],
    veil_pk: &[u8],
    role: u8,
    not_before: i64,
    not_after: i64,
    suite_id: u8,
    scope: &str,
    sig: &[u8; 64],
) -> Vec<u8> {
    let scope_bytes = scope.as_bytes();
    let mut out = Vec::with_capacity(67 + scope_bytes.len() + 64);
    out.extend_from_slice(ticket_id); // 16
    out.extend_from_slice(veil_pk); // 32
    out.push(role); // 1
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

    let minted = mint_capability_b2(
        &ctx.issuer,
        relay_address,
        relay,
        ctx.ticket_ttl_secs,
        unix_now(),
    );

    sqlx::query(
        "INSERT INTO veil_tickets \
         (ticket_id, auth_key, user_id, relay_scope, not_before, not_after, suite_id) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(&minted.ticket_id)
    .bind(&minted.auth_key)
    .bind(user_id)
    .bind(&minted.relay_scope)
    .bind(minted.not_before)
    .bind(minted.issued.not_after)
    .bind(minted.suite_id as i16)
    .execute(&*ctx.db_pool)
    .await?;

    Ok(minted.issued)
}

/// Issue (sign + persist) a fresh **key-bound** (B1) capability for `user_id` on
/// `relay_address`, bound to the holder's `veil_pk`. No bearer secret is generated
/// or stored — the relay verifies the holder's own signature over the exporter
/// (`AuthRecordV3`), so this table holds only public accounting data.
pub async fn issue_capability_v2(
    ctx: &VeilServiceContext,
    user_id: Uuid,
    relay_address: &str,
    veil_pk: &[u8],
    role: u32,
) -> Result<IssuedCapability, IssueError> {
    let veil_pk: [u8; VEIL_PK_LEN] = veil_pk
        .try_into()
        .map_err(|_| IssueError::InvalidVeilPk(veil_pk.len()))?;
    let role: u8 = match role {
        r if r == ROLE_USER as u32 => ROLE_USER,
        r if r == ROLE_RELAY as u32 => ROLE_RELAY,
        r => return Err(IssueError::InvalidRole(r)),
    };

    let relay = ctx
        .relays
        .get(relay_address)
        .ok_or_else(|| IssueError::UnknownRelay(relay_address.to_string()))?;

    let minted = mint_capability_v2(
        &ctx.issuer,
        relay_address,
        relay,
        veil_pk,
        role,
        ctx.ticket_ttl_secs,
        unix_now(),
    );

    sqlx::query(
        "INSERT INTO veil_capabilities_v2 \
         (ticket_id, veil_pk, role, user_id, relay_scope, not_before, not_after, suite_id) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(&minted.ticket_id[..])
    .bind(&minted.veil_pk[..])
    .bind(minted.role as i16)
    .bind(user_id)
    .bind(&minted.relay_scope)
    .bind(minted.not_before)
    .bind(minted.issued.not_after)
    .bind(minted.suite_id as i16)
    .execute(&*ctx.db_pool)
    .await?;

    Ok(minted.issued)
}

/// Issue one capability, dispatching bearer (B2) vs key-bound (B1) exactly as the
/// public RPC does: an empty `veil_pk` yields a bearer capability, otherwise a
/// key-bound one bound to `veil_pk`/`role`.
async fn issue_one(
    ctx: &VeilServiceContext,
    user_id: Uuid,
    relay_address: &str,
    veil_pk: &[u8],
    role: u32,
) -> Result<IssuedCapability, IssueError> {
    if veil_pk.is_empty() {
        issue_capability(ctx, user_id, relay_address).await
    } else {
        issue_capability_v2(ctx, user_id, relay_address, veil_pk, role).await
    }
}

/// Stable, dependency-free rank for `(user_id, addr, epoch)` (FNV-1a-64). Used only to
/// pick a rotating alternate subset; it is not a security primitive — enumeration is
/// bounded by K, not by this hash's unpredictability.
fn alt_rank(user_id: Uuid, addr: &str, epoch: i64) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut h = FNV_OFFSET;
    let mut mix = |bytes: &[u8]| {
        for &b in bytes {
            h ^= b as u64;
            h = h.wrapping_mul(FNV_PRIME);
        }
    };
    mix(user_id.as_bytes());
    mix(addr.as_bytes());
    mix(&epoch.to_le_bytes());
    h
}

/// Deterministically pick up to `k` alternate relay addresses (excluding `primary`)
/// for this user in the current epoch. Stable within an epoch, rotates across epochs.
fn select_alternate_addresses(
    relays: &HashMap<String, RelayInfo>,
    primary: &str,
    user_id: Uuid,
    k: usize,
    epoch: i64,
) -> Vec<String> {
    if k == 0 {
        return Vec::new();
    }
    let mut ranked: Vec<(u64, &String)> = relays
        .keys()
        .filter(|a| a.as_str() != primary)
        .map(|a| (alt_rank(user_id, a, epoch), a))
        .collect();
    // Primary sort by rank; tie-break by address so the order is fully deterministic.
    ranked.sort_unstable_by(|x, y| x.0.cmp(&y.0).then_with(|| x.1.cmp(y.1)));
    ranked.into_iter().take(k).map(|(_, a)| a.clone()).collect()
}

/// A primary capability plus its pre-issued alternate fronts (EntryDirectory v1).
pub struct IssuedBundle {
    pub primary: IssuedCapability,
    /// Up to K capabilities on *other* configured relays, chosen per-user/epoch.
    pub alternates: Vec<IssuedCapability>,
}

/// Issue the primary capability for `relay_address` and pre-issue up to `k` alternates
/// on other configured relays (in-band ranked handout, `decisions/entry-directory-design.md`).
///
/// Alternates use the **same** issuance path (bearer vs key-bound) as the primary, so a
/// key-bound request yields key-bound alternates bound to the same `veil_pk`. If ≤1 relay
/// is configured, `alternates` is empty and behaviour is identical to the pre-v1 handler.
///
/// Empty `relay_address` is resolved via [`resolve_primary_relay`] (single-relay default)
/// so auto first-issue clients that omit the field still work in the common N=1 deploy.
pub async fn issue_bundle(
    ctx: &VeilServiceContext,
    user_id: Uuid,
    relay_address: &str,
    veil_pk: &[u8],
    role: u32,
    k: usize,
) -> Result<IssuedBundle, IssueError> {
    let primary_addr = resolve_primary_relay(&ctx.relays, relay_address)?.to_string();
    let primary = issue_one(ctx, user_id, &primary_addr, veil_pk, role).await?;

    let epoch = unix_now() / ALT_ROTATION_SECS;
    let alt_addrs = select_alternate_addresses(&ctx.relays, &primary_addr, user_id, k, epoch);

    let mut alternates = Vec::with_capacity(alt_addrs.len());
    for addr in alt_addrs {
        // A single misconfigured alternate must not fail the whole issuance — the
        // primary already succeeded. Skip and log; the client still gets a usable set.
        match issue_one(ctx, user_id, &addr, veil_pk, role).await {
            Ok(cap) => alternates.push(cap),
            Err(e) => tracing::warn!(relay = %addr, error = %e, "skipping alternate front"),
        }
    }

    Ok(IssuedBundle {
        primary,
        alternates,
    })
}

/// Pure EntryDirectory planning step: given N configured relays, return the primary
/// address (after resolve) and the K alternate addresses that *would* be issued.
/// No minting / no DB — used by tests and diagnostics.
pub fn plan_bundle_addresses(
    relays: &HashMap<String, RelayInfo>,
    relay_address: &str,
    user_id: Uuid,
    k: usize,
    epoch: i64,
) -> Result<(String, Vec<String>), IssueError> {
    let primary = resolve_primary_relay(relays, relay_address)?.to_string();
    let alts = select_alternate_addresses(relays, &primary, user_id, k, epoch);
    Ok((primary, alts))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, Verifier, VerifyingKey};

    fn relay_set(addrs: &[&str]) -> HashMap<String, RelayInfo> {
        addrs
            .iter()
            .map(|a| {
                (
                    a.to_string(),
                    RelayInfo {
                        scope: "ru".into(),
                        spki: format!("pin-{a}"),
                        sni: format!("sni-{a}"),
                    },
                )
            })
            .collect()
    }

    fn test_issuer() -> SigningKey {
        SigningKey::from_bytes(&[9u8; 32])
    }

    /// Offline B2 verify — same checks a relay performs (domain + window layout).
    fn verify_b2_blob(vk: &VerifyingKey, blob: &[u8], expected_scope: &str) -> bool {
        let fixed = 66; // through scope_len
        if blob.len() < fixed + 64 {
            return false;
        }
        let scope_len = blob[65] as usize;
        if blob.len() != fixed + scope_len + 64 {
            return false;
        }
        let scope = &blob[66..66 + scope_len];
        if scope != expected_scope.as_bytes() {
            return false;
        }
        let sig_bytes: [u8; 64] = match blob[66 + scope_len..].try_into() {
            Ok(s) => s,
            Err(_) => return false,
        };
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        // message = "veil-cap-v1" || blob[0..65] || scope  (no scope_len)
        let mut msg = CAP_DOMAIN.to_vec();
        msg.extend_from_slice(&blob[0..65]);
        msg.extend_from_slice(scope);
        vk.verify(&msg, &sig).is_ok()
    }

    fn verify_v2_blob(vk: &VerifyingKey, blob: &[u8], expected_scope: &str) -> bool {
        let fixed = 67;
        if blob.len() < fixed + 64 {
            return false;
        }
        let scope_len = blob[66] as usize;
        if blob.len() != fixed + scope_len + 64 {
            return false;
        }
        let scope = &blob[67..67 + scope_len];
        if scope != expected_scope.as_bytes() {
            return false;
        }
        let sig_bytes: [u8; 64] = match blob[67 + scope_len..].try_into() {
            Ok(s) => s,
            Err(_) => return false,
        };
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        let mut msg = CAP_V2_DOMAIN.to_vec();
        msg.extend_from_slice(&blob[0..66]);
        msg.extend_from_slice(scope);
        vk.verify(&msg, &sig).is_ok()
    }

    #[test]
    fn alternates_exclude_primary_and_bound_by_k() {
        let relays = relay_set(&["a:1", "b:1", "c:1", "d:1"]);
        let user = Uuid::from_u128(42);
        let alts = select_alternate_addresses(&relays, "a:1", user, 2, 100);
        assert_eq!(alts.len(), 2);
        assert!(!alts.contains(&"a:1".to_string()));
    }

    #[test]
    fn alternates_stable_within_epoch_rotate_across_epochs() {
        let relays = relay_set(&["a:1", "b:1", "c:1", "d:1", "e:1"]);
        let user = Uuid::from_u128(7);
        let e0a = select_alternate_addresses(&relays, "a:1", user, 3, 100);
        let e0b = select_alternate_addresses(&relays, "a:1", user, 3, 100);
        assert_eq!(e0a, e0b, "selection must be stable within an epoch");
        // Across many epochs the set should not be frozen (rotation happens).
        let rotated = (101..200)
            .any(|epoch| select_alternate_addresses(&relays, "a:1", user, 3, epoch) != e0a);
        assert!(rotated, "selection must rotate across epochs");
    }

    #[test]
    fn fewer_relays_than_k_yields_all_others() {
        let relays = relay_set(&["a:1", "b:1"]);
        let user = Uuid::from_u128(1);
        let alts = select_alternate_addresses(&relays, "a:1", user, 3, 100);
        assert_eq!(alts, vec!["b:1".to_string()]);
    }

    #[test]
    fn single_relay_yields_no_alternates() {
        let relays = relay_set(&["a:1"]);
        let user = Uuid::from_u128(1);
        assert!(select_alternate_addresses(&relays, "a:1", user, 3, 100).is_empty());
    }

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

    #[test]
    fn v2_blob_layout_is_canonical_length() {
        // 16 + 32 + 1 + 8 + 8 + 1 + 1 + scope + 64
        let sig = [0u8; 64];
        let blob = encode_capability_v2(&[1; 16], &[2; 32], ROLE_RELAY, 0, 100, 1, "ru", &sig);
        assert_eq!(blob.len(), 67 + 2 + 64);
        assert_eq!(blob[48], ROLE_RELAY);
        // scope length byte is at offset 66, scope bytes follow.
        assert_eq!(blob[66], 2);
        assert_eq!(&blob[67..69], b"ru");
    }

    #[test]
    fn v2_signing_message_is_domain_separated() {
        let m = signing_message_v2(&[1; 16], &[2; 32], ROLE_USER, 0, 100, 1, "ru");
        assert!(m.starts_with(b"veil-cap-v2"));
        // domain(11) + ticket_id(16) + veil_pk(32) + role(1) + nb(8) + na(8) + suite(1) + scope(2)
        assert_eq!(m.len(), 11 + 66 + 2);
    }

    /// Cross-repo interop anchor: must match construct-veil-protocol's
    /// `capability::golden::capability_v2_blob_matches_golden_vector` exactly.
    #[test]
    fn backend_v2_blob_matches_protocol_golden() {
        const GOLDEN: &str = "010101010101010101010101010101010202020202020202020202020202020202020202020202020202020202020202010000000000000000640000000000000001027275548ee6e76270611644a8c7ac26407d6c9aed69e375472ee445384f0936661d7cdf3c08b88e448aa1d349f8e6f544fb26662bdbdc99ca2c412fdc232cfee49f06";
        let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let ticket_id = [1u8; 16];
        let veil_pk = [2u8; 32];
        let msg = signing_message_v2(&ticket_id, &veil_pk, ROLE_RELAY, 0, 100, 1, "ru");
        let sig: [u8; 64] = sk.sign(&msg).to_bytes();
        let blob = encode_capability_v2(&ticket_id, &veil_pk, ROLE_RELAY, 0, 100, 1, "ru", &sig);
        assert_eq!(hex::encode(&blob), GOLDEN);
    }

    #[test]
    fn invalid_veil_pk_length_is_rejected() {
        let err = IssueError::InvalidVeilPk(31);
        assert!(err.to_string().contains("32"));
    }

    // ── parse / resolve / mint (auto first-issue support) ───────────────────

    #[test]
    fn parse_relays_spec_happy_and_skip_malformed() {
        let (relays, skipped) = parse_relays_spec(
            "a.example:443,ru,aa,sni-a; bad-record; b.example:443, eu , bb , sni-b ;",
        );
        assert_eq!(skipped, 1);
        assert_eq!(relays.len(), 2);
        assert_eq!(relays["a.example:443"].scope, "ru");
        assert_eq!(relays["a.example:443"].spki, "aa");
        assert_eq!(relays["b.example:443"].scope, "eu");
        assert_eq!(relays["b.example:443"].sni, "sni-b");
    }

    #[test]
    fn parse_relays_spec_empty_is_empty() {
        let (relays, skipped) = parse_relays_spec("");
        assert!(relays.is_empty());
        assert_eq!(skipped, 0);
        let (relays, skipped) = parse_relays_spec(";;;");
        assert!(relays.is_empty());
        assert_eq!(skipped, 0);
    }

    #[test]
    fn merge_legacy_does_not_override_multi() {
        let mut relays = parse_relays_spec("a:1,ru,pin-a,sni-a").0;
        merge_legacy_relay(&mut relays, "a:1", "other", "pin-other", "sni-other");
        assert_eq!(relays["a:1"].spki, "pin-a", "VEIL_RELAYS wins over legacy");
        merge_legacy_relay(&mut relays, "b:1", "eu", "pin-b", "sni-b");
        assert_eq!(relays.len(), 2);
        assert_eq!(relays["b:1"].scope, "eu");
    }

    #[test]
    fn resolve_primary_empty_with_single_relay() {
        let relays = relay_set(&["only:443"]);
        assert_eq!(resolve_primary_relay(&relays, "").unwrap(), "only:443");
        assert_eq!(
            resolve_primary_relay(&relays, "  only:443  ").unwrap(),
            "only:443"
        );
    }

    #[test]
    fn resolve_primary_empty_with_multi_requires_address() {
        let relays = relay_set(&["a:1", "b:1"]);
        match resolve_primary_relay(&relays, "") {
            Err(IssueError::RelayAddressRequired) => {}
            other => panic!("expected RelayAddressRequired, got {other:?}"),
        }
    }

    #[test]
    fn resolve_primary_empty_with_none_is_no_relays() {
        let relays = HashMap::new();
        match resolve_primary_relay(&relays, "") {
            Err(IssueError::NoRelaysConfigured) => {}
            other => panic!("expected NoRelaysConfigured, got {other:?}"),
        }
    }

    #[test]
    fn resolve_primary_unknown_is_error() {
        let relays = relay_set(&["a:1"]);
        match resolve_primary_relay(&relays, "ghost:443") {
            Err(IssueError::UnknownRelay(r)) => assert_eq!(r, "ghost:443"),
            other => panic!("expected UnknownRelay, got {other:?}"),
        }
    }

    #[test]
    fn plan_bundle_single_relay_no_alternates() {
        let relays = relay_set(&["a:1"]);
        let (primary, alts) =
            plan_bundle_addresses(&relays, "", Uuid::from_u128(1), DEFAULT_ALTERNATES_K, 0)
                .unwrap();
        assert_eq!(primary, "a:1");
        assert!(alts.is_empty());
    }

    #[test]
    fn plan_bundle_multi_k3_excludes_primary() {
        let relays = relay_set(&["a:1", "b:1", "c:1", "d:1", "e:1"]);
        let user = Uuid::from_u128(99);
        let (primary, alts) =
            plan_bundle_addresses(&relays, "a:1", user, DEFAULT_ALTERNATES_K, 42).unwrap();
        assert_eq!(primary, "a:1");
        assert_eq!(alts.len(), 3);
        assert!(!alts.contains(&"a:1".to_string()));
        // Stable: re-plan yields same set.
        let (_, alts2) =
            plan_bundle_addresses(&relays, "a:1", user, DEFAULT_ALTERNATES_K, 42).unwrap();
        assert_eq!(alts, alts2);
    }

    #[test]
    fn mint_b2_blob_verifies_offline_and_carries_coords() {
        let issuer = test_issuer();
        let vk = issuer.verifying_key();
        let relay = RelayInfo {
            scope: "ru".into(),
            spki: "deadbeef".into(),
            sni: "front.example".into(),
        };
        let now = 1_700_000_000i64;
        let minted = mint_capability_b2(&issuer, "front.example:443", &relay, 3600, now);
        assert_eq!(minted.issued.capability_version, 1);
        assert_eq!(minted.issued.relay_address, "front.example:443");
        assert_eq!(minted.issued.spki, "deadbeef");
        assert_eq!(minted.issued.sni, "front.example");
        assert_eq!(minted.issued.not_after, now + 3600);
        assert_eq!(minted.ticket_id.len(), 16);
        assert_eq!(minted.auth_key.len(), 32);
        assert!(
            verify_b2_blob(&vk, &minted.issued.blob, "ru"),
            "relay-side offline verify must accept backend mint"
        );
    }

    #[test]
    fn mint_v2_blob_verifies_offline_and_binds_veil_pk() {
        let issuer = test_issuer();
        let vk = issuer.verifying_key();
        let relay = RelayInfo {
            scope: "ru".into(),
            spki: "pin".into(),
            sni: "sni".into(),
        };
        let veil_pk = [0xABu8; 32];
        let minted = mint_capability_v2(
            &issuer,
            "front:443",
            &relay,
            veil_pk,
            ROLE_USER,
            DEFAULT_TICKET_TTL_SECS,
            1_700_000_000,
        );
        assert_eq!(minted.issued.capability_version, 2);
        assert_eq!(&minted.issued.blob[16..48], &veil_pk);
        assert_eq!(minted.issued.blob[48], ROLE_USER);
        assert!(verify_v2_blob(&vk, &minted.issued.blob, "ru"));
    }

    #[test]
    fn mint_v2_role_relay_is_encoded() {
        let issuer = test_issuer();
        let relay = RelayInfo {
            scope: "".into(),
            spki: "p".into(),
            sni: "s".into(),
        };
        let minted = mint_capability_v2(&issuer, "r:443", &relay, [1u8; 32], ROLE_RELAY, 60, 100);
        assert_eq!(minted.role, ROLE_RELAY);
        assert_eq!(minted.issued.blob[48], ROLE_RELAY);
    }

    #[test]
    fn two_mints_are_distinct() {
        // Auto first-issue / renew must never re-issue the same ticket_id.
        let issuer = test_issuer();
        let relay = RelayInfo {
            scope: "ru".into(),
            spki: "p".into(),
            sni: "s".into(),
        };
        let a = mint_capability_b2(&issuer, "r:1", &relay, 60, 100);
        let b = mint_capability_b2(&issuer, "r:1", &relay, 60, 100);
        assert_ne!(a.ticket_id, b.ticket_id);
        assert_ne!(a.auth_key, b.auth_key);
        assert_ne!(a.issued.blob, b.issued.blob);
    }
}
