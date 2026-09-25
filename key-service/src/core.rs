// ============================================================================
// KeyService Core - Database Operations
// ============================================================================

use anyhow::Result;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sqlx::PgPool;

// ============================================================================
// Types
// ============================================================================

/// ML-KEM-1024 public key size in bytes (NIST FIPS 203). Until PQXDH v2 this constant said
/// "ML-KEM-1024" and held 1184 — the ML-KEM-768 size, which is what clients actually sent.
pub const KYBER_PUBLIC_KEY_SIZE: usize = 1568;
/// ML-KEM-1024 ciphertext size in bytes (carried in PreKeySignalMessage.kem_ciphertext)
#[allow(dead_code)]
pub const KYBER_CIPHERTEXT_SIZE: usize = 1568;
/// Ed25519 signature size in bytes
pub const ED25519_SIGNATURE_SIZE: usize = 64;

/// The oldest a Kyber signed pre-key may be, by its signed `created_at`, when it is uploaded.
///
/// construct-core's `KYBER_SPK_MAX_AGE_SECS`: an initiator refuses to encapsulate to an older
/// one, so storing it would publish a bundle every peer rejects.
pub const KYBER_SPK_MAX_AGE_SECS: u64 = 30 * 24 * 3600;

/// How far in the future a signed `created_at` may be (device clock skew).
pub const KYBER_CREATED_AT_MAX_SKEW_SECS: u64 = 24 * 3600;

/// Warn in logs when a served SPK is older than 8 days. Clients will reject at 10 days.
const SPK_WARN_AGE_SECS: i64 = 8 * 24 * 3600;

/// Fire a wake push when a served SPK is older than 21 days.
/// Sits below the client-side 30-day hard-reject limit, with margin for the
/// wake → rotate → re-publish round-trip. Well above the 8-day warn threshold
/// so active users who rotate on schedule are never woken.
const SPK_WAKE_AGE_SECS: i64 = 21 * 24 * 3600;

#[derive(Debug, Clone)]
pub struct PreKeyBundle {
    pub device_id: String,
    pub identity_key: Vec<u8>,
    pub verifying_key: Vec<u8>,
    pub signed_prekey: Vec<u8>,
    pub signed_prekey_id: u32,
    pub signed_prekey_signature: Vec<u8>,
    pub one_time_prekey: Option<Vec<u8>>,
    pub one_time_prekey_id: Option<u32>,
    pub crypto_suite: String,
    pub registered_at: DateTime<Utc>,
    // ---- Post-Quantum (ML-KEM-1024) fields — absent when device has no Kyber keys ----
    pub kyber_pre_key: Option<Vec<u8>>,
    pub kyber_pre_key_id: Option<u32>,
    pub kyber_pre_key_signature: Option<Vec<u8>>,
    pub kyber_one_time_pre_key: Option<Vec<u8>>,
    pub kyber_one_time_pre_key_id: Option<u32>,
    // ---- PQXDH v2 (migration 071): what the device signed alongside each Kyber key ----
    /// Signed creation time of the Kyber SPK (unix seconds), under both of its signatures.
    pub kyber_pre_key_created_at: Option<u64>,
    /// Ed25519 signature over the Kyber OTPK's v2 sign-message.
    pub kyber_one_time_pre_key_signature: Option<Vec<u8>>,
    /// Signed creation time of the Kyber OTPK.
    pub kyber_one_time_pre_key_created_at: Option<u64>,
    /// Hybrid signature over the Kyber OTPK's v2 sign-message.
    pub kyber_one_time_pre_key_hybrid_signature: Option<Vec<u8>>,
    // ---- SPK timestamps and rotation epochs (migration 031) ----
    pub spk_uploaded_at: Option<DateTime<Utc>>,
    pub spk_rotation_epoch: u32,
    pub kyber_spk_uploaded_at: Option<DateTime<Utc>>,
    pub kyber_spk_rotation_epoch: u32,
    /// Ed25519 signature over canonical bundle bytes (see `sign_bundle`).
    /// `None` when bundle signing key is not configured (dev/test environments).
    pub bundle_signature: Option<Vec<u8>>,
    /// Key Transparency inclusion proof. `None` when KT log is not populated
    /// (dev/test environments or first registration before the leaf is visible).
    pub kt_proof: Option<crate::kt::KtProof>,
    // ---- Hybrid PQ identity signatures (Ed25519 + ML-DSA-65) — migration 053 ----
    // All `None` for Ed25519-only devices. Served in PreKeyBundle proto fields 20-23.
    /// Hybrid identity public key (1984 bytes). Independent Ed25519 half bound to the
    /// device identity by `hybrid_identity_signature` (cross-sign, no 0..32 invariant).
    pub hybrid_identity_key: Option<Vec<u8>>,
    /// Ed25519 cross-signature over `"KonstruktHybridId-v1" || hybrid_identity_key` (64 bytes).
    pub hybrid_identity_signature: Option<Vec<u8>>,
    /// Hybrid signature over the SPK X3DH sign-message (3373 bytes).
    pub signed_prekey_hybrid_signature: Option<Vec<u8>>,
    /// Hybrid signature over the Kyber SPK X3DH sign-message (3373 bytes).
    pub kyber_pre_key_hybrid_signature: Option<Vec<u8>>,
    /// KT inclusion proof for the hybrid identity key (leaf kind 1). `None` when the device
    /// has no hybrid key or the KT log is not populated (dev/test).
    pub hybrid_kt_proof: Option<crate::kt::KtProof>,

    /// Capability flag: device supports SuiteID::PQ_RATCHET (sparse continuous PQ ratchet).
    pub supports_pq_ratchet: bool,
}

#[derive(Debug, Clone)]
pub struct OneTimePreKey {
    pub key_id: u32,
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SignedPreKey {
    pub key_id: u32,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

/// ML-KEM-1024 one-time pre-key as a PQXDH v2 device uploads it: both signatures over
/// `"KonstruktX3DH-v1" || [0x00, 0x11] || created_at (u64 BE) || public_key`.
#[derive(Debug, Clone)]
pub struct KyberOneTimePreKey {
    pub key_id: u32,
    /// Exactly `KYBER_PUBLIC_KEY_SIZE` (1568) bytes
    pub public_key: Vec<u8>,
    /// Ed25519 signature, exactly `ED25519_SIGNATURE_SIZE` (64) bytes
    pub signature: Vec<u8>,
    /// Signed creation time, unix seconds
    pub created_at: u64,
    /// Hybrid signature (Ed25519 + ML-DSA-65), 3373 bytes
    pub hybrid_signature: Vec<u8>,
}

/// Validate ML-KEM-1024 public key size.
/// Returns `Err` if the key is not exactly 1568 bytes.
pub fn validate_kyber_public_key(key: &[u8]) -> Result<()> {
    if key.len() != KYBER_PUBLIC_KEY_SIZE {
        anyhow::bail!(
            "Invalid ML-KEM-1024 public key size: expected {} bytes, got {}",
            KYBER_PUBLIC_KEY_SIZE,
            key.len()
        );
    }
    Ok(())
}

/// Validate hybrid signature size (Ed25519 + ML-DSA-65 = 3373 bytes).
pub fn validate_hybrid_signature(sig: &[u8]) -> Result<()> {
    if sig.len() != construct_crypto::pqc::HYBRID_SIGNATURE_SIZE {
        anyhow::bail!(
            "Invalid hybrid signature size: expected {} bytes, got {}",
            construct_crypto::pqc::HYBRID_SIGNATURE_SIZE,
            sig.len()
        );
    }
    Ok(())
}

/// Validate Ed25519 signature size (used for Kyber key signatures).
/// Returns `Err` if the signature is not exactly 64 bytes.
pub fn validate_ed25519_signature(sig: &[u8]) -> Result<()> {
    if sig.len() != ED25519_SIGNATURE_SIZE {
        anyhow::bail!(
            "Invalid Ed25519 signature size: expected {} bytes, got {}",
            ED25519_SIGNATURE_SIZE,
            sig.len()
        );
    }
    Ok(())
}

/// Cryptographically verify a classic signed pre-key signature.
///
/// Message = `"KonstruktX3DH-v1" || [0x00, suite_id] || public_key`
///
/// `suite_id`: 0x01 = ClassicX25519. Kyber keys are checked by [`check_kyber_prekey_v2`].
pub fn verify_prekey_signature(
    verifying_key_bytes: &[u8],
    suite_id: u8,
    public_key: &[u8],
    signature_bytes: &[u8],
) -> Result<()> {
    let vk_array: [u8; 32] = verifying_key_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("verifying_key must be 32 bytes"))?;
    let vk = VerifyingKey::from_bytes(&vk_array)
        .map_err(|e| anyhow::anyhow!("Invalid verifying key: {}", e))?;

    let sig_array: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("signature must be 64 bytes"))?;
    let sig = Signature::from_bytes(&sig_array);

    let mut message = Vec::with_capacity(18 + public_key.len());
    message.extend_from_slice(b"KonstruktX3DH-v1");
    message.extend_from_slice(&[0x00, suite_id]);
    message.extend_from_slice(public_key);

    vk.verify(&message, &sig)
        .map_err(|_| anyhow::anyhow!("Prekey signature verification failed"))
}

/// The PQXDH v2 checks a Kyber prekey must pass before it is stored: size, a plausible signed
/// `created_at`, and the device's Ed25519 signature over the v2 sign-message.
///
/// `max_age_secs` is `Some(KYBER_SPK_MAX_AGE_SECS)` for a signed pre-key and `None` for a
/// one-time key, whose age decides nothing (a replayed, used one-time key meets a deleted
/// secret). The server checks what an initiator will check, so a key that every peer would
/// refuse is rejected here, where the device can hear about it, rather than served.
pub fn check_kyber_prekey_v2(
    verifying_key: &[u8],
    public_key: &[u8],
    created_at: u64,
    signature: &[u8],
    now: u64,
    max_age_secs: Option<u64>,
) -> Result<()> {
    validate_kyber_public_key(public_key)?;
    validate_ed25519_signature(signature)?;
    if created_at == 0 {
        anyhow::bail!("Kyber prekey created_at is required (PQXDH v2)");
    }
    if created_at > now.saturating_add(KYBER_CREATED_AT_MAX_SKEW_SECS) {
        anyhow::bail!("Kyber prekey created_at is in the future: {created_at} > {now}");
    }
    if let Some(max_age) = max_age_secs
        && now.saturating_sub(created_at) > max_age
    {
        anyhow::bail!(
            "Kyber signed pre-key is older than {} days by its signed created_at",
            max_age / 86400
        );
    }
    construct_crypto::pqc::verify_kyber_prekey_signature_v2(
        verifying_key,
        created_at,
        public_key,
        signature,
    )
}

/// The hybrid half of [`check_kyber_prekey_v2`]: the signature under the device's hybrid
/// identity key, over the same v2 sign-message.
pub fn check_kyber_prekey_hybrid_v2(
    hybrid_identity_key: Option<&[u8]>,
    public_key: &[u8],
    created_at: u64,
    hybrid_signature: &[u8],
) -> Result<()> {
    let hybrid_key = hybrid_identity_key.ok_or_else(|| {
        anyhow::anyhow!(
            "Kyber prekey hybrid signature provided but device has no hybrid identity key"
        )
    })?;
    validate_hybrid_signature(hybrid_signature)?;
    construct_crypto::pqc::verify_hybrid_kyber_prekey_signature_v2(
        hybrid_key,
        created_at,
        public_key,
        hybrid_signature,
    )
    .map_err(|e| anyhow::anyhow!("Kyber prekey hybrid signature verification failed: {e}"))
}

fn now_secs() -> u64 {
    Utc::now().timestamp().max(0) as u64
}

/// Build a canonical byte representation of the bundle for signing.
///
/// Canonical format (deterministic, length-prefixed):
/// `"KonstruktBundle-v1" || identity_key || signed_prekey || [optional: one_time_prekey] || [optional: kyber_pre_key]`
///
/// All optional fields are included only when present, each prefixed with a 4-byte big-endian length.
fn canonical_bundle_bytes(bundle: &PreKeyBundle) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);
    buf.extend_from_slice(b"KonstruktBundle-v1");
    // identity_key (length-prefixed)
    let ik_len = bundle.identity_key.len() as u32;
    buf.extend_from_slice(&ik_len.to_be_bytes());
    buf.extend_from_slice(&bundle.identity_key);
    // signed_prekey (length-prefixed)
    let spk_len = bundle.signed_prekey.len() as u32;
    buf.extend_from_slice(&spk_len.to_be_bytes());
    buf.extend_from_slice(&bundle.signed_prekey);
    // signed_prekey_signature (length-prefixed)
    let spk_sig_len = bundle.signed_prekey_signature.len() as u32;
    buf.extend_from_slice(&spk_sig_len.to_be_bytes());
    buf.extend_from_slice(&bundle.signed_prekey_signature);
    // one_time_prekey (length-prefixed, present=1 absent=0 marker)
    if let Some(otp) = &bundle.one_time_prekey {
        buf.extend_from_slice(&(otp.len() as u32).to_be_bytes());
        buf.extend_from_slice(otp);
    } else {
        buf.extend_from_slice(&0u32.to_be_bytes());
    }
    // kyber_pre_key (length-prefixed, present=1 absent=0 marker)
    if let Some(kpk) = &bundle.kyber_pre_key {
        buf.extend_from_slice(&(kpk.len() as u32).to_be_bytes());
        buf.extend_from_slice(kpk);
    } else {
        buf.extend_from_slice(&0u32.to_be_bytes());
    }
    buf
}

/// Sign a pre-key bundle with the server's Ed25519 signing key.
///
/// Returns a 64-byte signature over the canonical bundle representation.
/// Clients SHOULD verify this signature against the server's public key
/// retrieved from `/.well-known/construct-server`.
pub fn sign_bundle(bundle: &PreKeyBundle, signing_key: &SigningKey) -> Vec<u8> {
    let canonical = canonical_bundle_bytes(bundle);
    let signature: Signature = signing_key.sign(&canonical);
    signature.to_bytes().to_vec()
}

/// Emit a warning when a bundle's SPK is older than `SPK_WARN_AGE_SECS` (8 days).
/// Clients will hard-reject at 10 days, so this gives a 2-day window to investigate.
/// Also warns when a PQ device has `kyber_spk_rotation_epoch == 0` (Kyber SPK never uploaded).
fn warn_if_spk_aging(bundle: &PreKeyBundle) {
    let now = Utc::now();
    let check = |uploaded_at: Option<DateTime<Utc>>, label: &str| {
        if let Some(ts) = uploaded_at {
            let age_secs = (now - ts).num_seconds();
            if age_secs > SPK_WARN_AGE_SECS {
                tracing::warn!(
                    device_id = %bundle.device_id,
                    age_days = age_secs / 86400,
                    label,
                    "SPK aging: client will reject in <2 days if key not rotated"
                );
            }
        }
    };
    check(bundle.spk_uploaded_at, "spk");
    check(bundle.kyber_spk_uploaded_at, "kyber_spk");

    // PQ-hybrid devices (0x10) must always have a non-zero Kyber SPK epoch.
    // epoch == 0 means the Kyber SPK was never uploaded; the bundle is incomplete.
    // Clients will refuse to initiate a PQ session against such a bundle.
    if bundle.crypto_suite == "0x10" && bundle.kyber_spk_rotation_epoch == 0 {
        tracing::warn!(
            device_id = %bundle.device_id,
            crypto_suite = %bundle.crypto_suite,
            "PQ device has kyber_spk_rotation_epoch=0 — Kyber SPK was never uploaded; \
             clients will reject this bundle for PQ session init"
        );
    }
}

/// Returns `true` if any of the bundle's SPKs is old enough to warrant a
/// rotation wake push (> `SPK_WAKE_AGE_SECS`). Used by key-service main.rs
/// to decide whether to fire-and-forget a `SendKeyRotationWake`.
///
/// Always returns `false` when the bundle has no `spk_uploaded_at` timestamp
/// (shouldn't happen for active devices, but safe to skip).
pub fn spk_is_stale_enough_for_wake(bundle: &PreKeyBundle) -> bool {
    let now = Utc::now();
    let check = |ts: Option<DateTime<Utc>>| -> bool {
        ts.is_some_and(|t| (now - t).num_seconds() > SPK_WAKE_AGE_SECS)
    };
    check(bundle.spk_uploaded_at) || check(bundle.kyber_spk_uploaded_at)
}

/// Get pre-key bundle for a device (consumes one-time pre-key if available)
pub async fn get_prekey_bundle(
    db: &PgPool,
    user_id: &str,
    device_id: Option<&str>,
    bundle_signing_key: Option<&SigningKey>,
    // When false, serve an SPK-only bundle without consuming a one-time pre-key. Used by the
    // OTPK-drain guard: above the drain threshold we degrade to SPK-only (forward-secrecy
    // reduced but session init still works) instead of rejecting — this preserves availability
    // and removes the targeted-DoS amplification a hard reject would create. Mirrors the natural
    // fallback when a device's OTPKs are genuinely exhausted.
    consume_otpk: bool,
) -> Result<Option<PreKeyBundle>> {
    // First, get device info (including Kyber SPK columns added in migration 028)
    let device = if let Some(did) = device_id {
        sqlx::query_as::<_, DeviceRow>(
            r#"
            SELECT device_id, identity_public, verifying_key, signed_prekey_public,
                   signed_prekey_id, signed_prekey_signature, crypto_suites->>0 AS crypto_suite, registered_at,
                   kyber_signed_pre_key, kyber_signed_pre_key_id, kyber_signed_pre_key_signature,
                   kyber_signed_pre_key_created_at,
                   spk_uploaded_at, spk_rotation_epoch, kyber_spk_uploaded_at, kyber_spk_rotation_epoch,
                   hybrid_identity_key, hybrid_identity_signature,
                   signed_prekey_hybrid_signature, kyber_signed_pre_key_hybrid_signature,
                   supports_pq_ratchet
            FROM devices
            WHERE device_id = $1 AND user_id = $2::uuid AND is_active = true
            "#,
        )
        .bind(did)
        .bind(user_id)
        .fetch_optional(db)
        .await?
    } else {
        // Get primary device (first registered)
        sqlx::query_as::<_, DeviceRow>(
            r#"
            SELECT device_id, identity_public, verifying_key, signed_prekey_public,
                   signed_prekey_id, signed_prekey_signature, crypto_suites->>0 AS crypto_suite, registered_at,
                   kyber_signed_pre_key, kyber_signed_pre_key_id, kyber_signed_pre_key_signature,
                   kyber_signed_pre_key_created_at,
                   spk_uploaded_at, spk_rotation_epoch, kyber_spk_uploaded_at, kyber_spk_rotation_epoch,
                   hybrid_identity_key, hybrid_identity_signature,
                   signed_prekey_hybrid_signature, kyber_signed_pre_key_hybrid_signature,
                   supports_pq_ratchet
            FROM devices
            WHERE user_id = $1::uuid AND is_active = true
            ORDER BY registered_at ASC
            LIMIT 1
            "#,
        )
        .bind(user_id)
        .fetch_optional(db)
        .await?
    };

    let device = match device {
        Some(d) => d,
        None => return Ok(None),
    };

    // Try to consume a one-time pre-key (skip expired ones from a previous replace_existing).
    // FOR UPDATE SKIP LOCKED prevents two concurrent GetPreKeyBundle calls from burning the same key.
    // Skipped entirely when `consume_otpk` is false (drain guard → SPK-only bundle).
    let otp = if consume_otpk {
        sqlx::query_as::<_, OneTimePreKeyRow>(
            r#"
            DELETE FROM one_time_prekeys
            WHERE (device_id, key_id) = (
                SELECT device_id, key_id FROM one_time_prekeys
                WHERE device_id = $1
                  AND is_expired = false
                ORDER BY uploaded_at ASC
                LIMIT 1
                FOR UPDATE SKIP LOCKED
            )
            RETURNING key_id, public_key
            "#,
        )
        .bind(&device.device_id)
        .fetch_optional(db)
        .await?
    } else {
        None
    };

    // Counted here rather than at the call site because this is the only place a
    // key actually leaves the pool: `consume_otpk` false (drain guard) and an
    // empty pool both land in the `None` branch, and neither is a consumption.
    if otp.is_some() {
        construct_metrics::OTPK_CONSUMED_TOTAL.inc();
    }

    // Try to consume a Kyber one-time pre-key (soft-delete, same pattern as classic OTPK)
    let kyber_otp = if consume_otpk {
        sqlx::query_as::<_, KyberOneTimePreKeyRow>(
            r#"
            UPDATE kyber_one_time_pre_keys
            SET is_expired = true, expired_at = NOW()
            WHERE (device_id, key_id) = (
                SELECT device_id, key_id FROM kyber_one_time_pre_keys
                WHERE device_id = $1
                  AND is_expired = false
                ORDER BY uploaded_at ASC
                LIMIT 1
                FOR UPDATE SKIP LOCKED
            )
            RETURNING key_id, public_key, signature, created_at, hybrid_signature
            "#,
        )
        .bind(&device.device_id)
        .fetch_optional(db)
        .await?
    } else {
        None
    };

    let mut bundle = PreKeyBundle {
        device_id: device.device_id,
        identity_key: device.identity_public,
        verifying_key: device.verifying_key,
        signed_prekey: device.signed_prekey_public,
        signed_prekey_id: device.signed_prekey_id as u32,
        signed_prekey_signature: device.signed_prekey_signature.unwrap_or_default(),
        one_time_prekey: otp.as_ref().map(|k| k.public_key.clone()),
        one_time_prekey_id: otp.as_ref().map(|k| k.key_id as u32),
        crypto_suite: device.crypto_suite,
        registered_at: device.registered_at,
        kyber_pre_key: device.kyber_signed_pre_key,
        kyber_pre_key_id: device.kyber_signed_pre_key_id.map(|id| id as u32),
        kyber_pre_key_signature: device.kyber_signed_pre_key_signature,
        kyber_one_time_pre_key: kyber_otp.as_ref().map(|k| k.public_key.clone()),
        kyber_one_time_pre_key_id: kyber_otp.as_ref().map(|k| k.key_id as u32),
        kyber_pre_key_created_at: device
            .kyber_signed_pre_key_created_at
            .map(|t| t.max(0) as u64),
        kyber_one_time_pre_key_signature: kyber_otp.as_ref().map(|k| k.signature.clone()),
        kyber_one_time_pre_key_created_at: kyber_otp
            .as_ref()
            .and_then(|k| k.created_at)
            .map(|t| t.max(0) as u64),
        kyber_one_time_pre_key_hybrid_signature: kyber_otp
            .as_ref()
            .and_then(|k| k.hybrid_signature.clone()),
        spk_uploaded_at: device.spk_uploaded_at,
        spk_rotation_epoch: device.spk_rotation_epoch as u32,
        kyber_spk_uploaded_at: device.kyber_spk_uploaded_at,
        kyber_spk_rotation_epoch: device.kyber_spk_rotation_epoch as u32,
        bundle_signature: None,
        kt_proof: None,
        hybrid_identity_key: device.hybrid_identity_key,
        hybrid_identity_signature: device.hybrid_identity_signature,
        signed_prekey_hybrid_signature: device.signed_prekey_hybrid_signature,
        kyber_pre_key_hybrid_signature: device.kyber_signed_pre_key_hybrid_signature,
        hybrid_kt_proof: None,
        supports_pq_ratchet: device.supports_pq_ratchet,
    };
    bundle.bundle_signature = bundle_signing_key.map(|sk| sign_bundle(&bundle, sk));
    if let Some(sk) = bundle_signing_key {
        match crate::kt::build_kt_proof(db, &bundle.device_id, &bundle.identity_key, sk).await {
            Ok(proof) => bundle.kt_proof = Some(proof),
            Err(e) => {
                tracing::warn!(error = %e, device_id = %bundle.device_id, "KT proof generation failed")
            }
        }
        bundle.hybrid_kt_proof = build_hybrid_kt_proof_if_present(db, &bundle, sk).await;
    }
    warn_if_spk_aging(&bundle);
    Ok(Some(bundle))
}

/// Build the hybrid KT inclusion proof when the device has a hybrid identity key.
/// Returns `None` (logged) on absence or error — KT is defense-in-depth, never fatal.
async fn build_hybrid_kt_proof_if_present(
    db: &PgPool,
    bundle: &PreKeyBundle,
    signing_key: &SigningKey,
) -> Option<crate::kt::KtProof> {
    let hybrid_key = bundle.hybrid_identity_key.as_ref()?;
    match crate::kt::build_hybrid_kt_proof(db, &bundle.device_id, hybrid_key, signing_key).await {
        Ok(proof) => Some(proof),
        Err(e) => {
            tracing::warn!(error = %e, device_id = %bundle.device_id, "Hybrid KT proof generation failed");
            None
        }
    }
}

/// Get pre-key bundles for all devices of a user
/// What a batch bundle fetch answered.
///
/// Three lists that are **not** subsets of one another, which is why they are named rather than
/// returned as a tuple: `bundles` is what could be built, `unavailable` is what exists but had no
/// keys to give, and `active_devices` is the account's device set — the only one of the three a
/// caller may prune against. See `GetPreKeyBundlesResponse.active_devices` in construct-protos.
pub struct PreKeyBundleSet {
    pub bundles: Vec<PreKeyBundle>,
    pub unavailable: Vec<String>,
    pub active_devices: Vec<String>,
}

pub async fn get_prekey_bundles(
    db: &PgPool,
    user_id: &str,
    device_ids: Option<&[String]>,
    bundle_signing_key: Option<&SigningKey>,
    // See `get_prekey_bundle`: false ⇒ SPK-only bundles (drain guard), no OTPK consumed.
    consume_otpk: bool,
) -> Result<PreKeyBundleSet> {
    // The account's device set, asked separately and always — `device_ids` narrows the bundle
    // query below, and deriving the set from a narrowed answer would report "these are the only
    // devices" about a query that only asked after some of them. Cheap: one indexed column.
    let active_devices: Vec<String> = sqlx::query_scalar(
        "SELECT device_id FROM devices WHERE user_id = $1::uuid AND is_active = true",
    )
    .bind(user_id)
    .fetch_all(db)
    .await?;

    let devices: Vec<DeviceRow> = if let Some(ids) = device_ids {
        sqlx::query_as(
            r#"
            SELECT device_id, identity_public, verifying_key, signed_prekey_public,
                   signed_prekey_id, signed_prekey_signature, crypto_suites->>0 AS crypto_suite, registered_at,
                   kyber_signed_pre_key, kyber_signed_pre_key_id, kyber_signed_pre_key_signature,
                   kyber_signed_pre_key_created_at,
                   spk_uploaded_at, spk_rotation_epoch, kyber_spk_uploaded_at, kyber_spk_rotation_epoch,
                   hybrid_identity_key, hybrid_identity_signature,
                   signed_prekey_hybrid_signature, kyber_signed_pre_key_hybrid_signature,
                   supports_pq_ratchet
            FROM devices
            WHERE user_id = $1::uuid AND device_id = ANY($2) AND is_active = true
            "#,
        )
        .bind(user_id)
        .bind(ids)
        .fetch_all(db)
        .await?
    } else {
        sqlx::query_as(
            r#"
            SELECT device_id, identity_public, verifying_key, signed_prekey_public,
                   signed_prekey_id, signed_prekey_signature, crypto_suites->>0 AS crypto_suite, registered_at,
                   kyber_signed_pre_key, kyber_signed_pre_key_id, kyber_signed_pre_key_signature,
                   kyber_signed_pre_key_created_at,
                   spk_uploaded_at, spk_rotation_epoch, kyber_spk_uploaded_at, kyber_spk_rotation_epoch,
                   hybrid_identity_key, hybrid_identity_signature,
                   signed_prekey_hybrid_signature, kyber_signed_pre_key_hybrid_signature,
                   supports_pq_ratchet
            FROM devices
            WHERE user_id = $1::uuid AND is_active = true
            "#,
        )
        .bind(user_id)
        .fetch_all(db)
        .await?
    };

    let mut bundles = Vec::new();
    let mut unavailable = Vec::new();

    for device in devices {
        // Try to get one-time pre-key (skip expired ones from a previous replace_existing).
        // FOR UPDATE SKIP LOCKED prevents two concurrent requests from burning the same key.
        // Skipped when `consume_otpk` is false (drain guard → SPK-only bundle).
        let otp = if consume_otpk {
            sqlx::query_as::<_, OneTimePreKeyRow>(
                r#"
                DELETE FROM one_time_prekeys
                WHERE (device_id, key_id) = (
                    SELECT device_id, key_id FROM one_time_prekeys
                    WHERE device_id = $1
                      AND is_expired = false
                    ORDER BY uploaded_at ASC
                    LIMIT 1
                    FOR UPDATE SKIP LOCKED
                )
                RETURNING key_id, public_key
                "#,
            )
            .bind(&device.device_id)
            .fetch_optional(db)
            .await?
        } else {
            None
        };

        // Same count in the batch path. Two call sites is the price of the two
        // query shapes; missing this one would have made the metric read low by
        // however much of the fleet fetches bundles in batches.
        if otp.is_some() {
            construct_metrics::OTPK_CONSUMED_TOTAL.inc();
        }

        // Try to consume a Kyber OTPK for this device
        let kyber_otp = if consume_otpk {
            sqlx::query_as::<_, KyberOneTimePreKeyRow>(
                r#"
                UPDATE kyber_one_time_pre_keys
                SET is_expired = true, expired_at = NOW()
                WHERE (device_id, key_id) = (
                    SELECT device_id, key_id FROM kyber_one_time_pre_keys
                    WHERE device_id = $1
                      AND is_expired = false
                    ORDER BY uploaded_at ASC
                    LIMIT 1
                    FOR UPDATE SKIP LOCKED
                )
                RETURNING key_id, public_key, signature, created_at, hybrid_signature
                "#,
            )
            .bind(&device.device_id)
            .fetch_optional(db)
            .await?
        } else {
            None
        };

        let mut bundle = PreKeyBundle {
            device_id: device.device_id,
            identity_key: device.identity_public,
            verifying_key: device.verifying_key,
            signed_prekey: device.signed_prekey_public,
            signed_prekey_id: device.signed_prekey_id as u32,
            signed_prekey_signature: device.signed_prekey_signature.unwrap_or_default(),
            one_time_prekey: otp.as_ref().map(|k| k.public_key.clone()),
            one_time_prekey_id: otp.as_ref().map(|k| k.key_id as u32),
            crypto_suite: device.crypto_suite,
            registered_at: device.registered_at,
            kyber_pre_key: device.kyber_signed_pre_key,
            kyber_pre_key_id: device.kyber_signed_pre_key_id.map(|id| id as u32),
            kyber_pre_key_signature: device.kyber_signed_pre_key_signature,
            kyber_one_time_pre_key: kyber_otp.as_ref().map(|k| k.public_key.clone()),
            kyber_one_time_pre_key_id: kyber_otp.as_ref().map(|k| k.key_id as u32),
            kyber_pre_key_created_at: device
                .kyber_signed_pre_key_created_at
                .map(|t| t.max(0) as u64),
            kyber_one_time_pre_key_signature: kyber_otp.as_ref().map(|k| k.signature.clone()),
            kyber_one_time_pre_key_created_at: kyber_otp
                .as_ref()
                .and_then(|k| k.created_at)
                .map(|t| t.max(0) as u64),
            kyber_one_time_pre_key_hybrid_signature: kyber_otp
                .as_ref()
                .and_then(|k| k.hybrid_signature.clone()),
            spk_uploaded_at: device.spk_uploaded_at,
            spk_rotation_epoch: device.spk_rotation_epoch as u32,
            kyber_spk_uploaded_at: device.kyber_spk_uploaded_at,
            kyber_spk_rotation_epoch: device.kyber_spk_rotation_epoch as u32,
            bundle_signature: None,
            kt_proof: None,
            hybrid_identity_key: device.hybrid_identity_key,
            hybrid_identity_signature: device.hybrid_identity_signature,
            signed_prekey_hybrid_signature: device.signed_prekey_hybrid_signature,
            kyber_pre_key_hybrid_signature: device.kyber_signed_pre_key_hybrid_signature,
            hybrid_kt_proof: None,
            supports_pq_ratchet: device.supports_pq_ratchet,
        };
        bundle.bundle_signature = bundle_signing_key.map(|sk| sign_bundle(&bundle, sk));
        if let Some(sk) = bundle_signing_key {
            match crate::kt::build_kt_proof(db, &bundle.device_id, &bundle.identity_key, sk).await {
                Ok(proof) => bundle.kt_proof = Some(proof),
                Err(e) => {
                    tracing::warn!(error = %e, device_id = %bundle.device_id, "KT proof generation failed")
                }
            }
            bundle.hybrid_kt_proof = build_hybrid_kt_proof_if_present(db, &bundle, sk).await;
        }
        warn_if_spk_aging(&bundle);
        bundles.push(bundle);
    }

    // Check for requested but unavailable devices
    if let Some(ids) = device_ids {
        let found: std::collections::HashSet<_> = bundles.iter().map(|b| &b.device_id).collect();
        for id in ids {
            if !found.contains(id) {
                unavailable.push(id.clone());
            }
        }
    }

    Ok(PreKeyBundleSet {
        bundles,
        unavailable,
        active_devices,
    })
}

// ============================================================================
// One-Time Pre-Key Management
// ============================================================================

/// Upload one-time pre-keys for a device.
/// If `replace_existing` is true, all existing keys for the device are
/// atomically deleted before the new batch is inserted (stale pool recovery).
/// If `kyber_pre_keys` is non-empty, those are also inserted into `kyber_one_time_pre_keys`.
/// Returns `(classic_count, kyber_count)`.
pub async fn upload_prekeys(
    db: &PgPool,
    device_id: &str,
    prekeys: &[OneTimePreKey],
    replace_existing: bool,
    kyber_pre_keys: &[KyberOneTimePreKey],
) -> Result<(u32, u32)> {
    // Verify device exists
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM devices WHERE device_id = $1 AND is_active = true)",
    )
    .bind(device_id)
    .fetch_one(db)
    .await?;

    if !exists {
        anyhow::bail!("Device not found or inactive");
    }

    // Verify every Kyber key before any DB write: both signatures over the v2 sign-message.
    // The hybrid one is required, not optional — a PQXDH v2 initiator uses a one-time key only
    // when both verify, so a key without it would be served and never used. The hybrid identity
    // key is read from the row, which is why the handler stores a hybrid identity sent in the
    // same request before calling this.
    if !kyber_pre_keys.is_empty() {
        let (verifying_key, hybrid_identity_key): (Vec<u8>, Option<Vec<u8>>) = sqlx::query_as(
            "SELECT verifying_key, hybrid_identity_key FROM devices WHERE device_id = $1 AND is_active = true",
        )
        .bind(device_id)
        .fetch_one(db)
        .await
        .map_err(|_| anyhow::anyhow!("Failed to fetch device verifying key"))?;

        let now = now_secs();
        for k in kyber_pre_keys {
            check_kyber_prekey_v2(
                &verifying_key,
                &k.public_key,
                k.created_at,
                &k.signature,
                now,
                None,
            )?;
            check_kyber_prekey_hybrid_v2(
                hybrid_identity_key.as_deref(),
                &k.public_key,
                k.created_at,
                &k.hybrid_signature,
            )?;
        }
    }

    // If replace_existing, soft-expire all current active keys instead of hard-deleting.
    // Keys are kept for 48 hours so any in-flight prekey messages can still be delivered.
    // Hard cleanup happens via cleanup_expired_otpks() on a schedule.
    if replace_existing {
        sqlx::query(
            "UPDATE one_time_prekeys
             SET is_expired = true, expired_at = NOW()
             WHERE device_id = $1 AND is_expired = false",
        )
        .bind(device_id)
        .execute(db)
        .await?;
        sqlx::query(
            "UPDATE kyber_one_time_pre_keys
             SET is_expired = true, expired_at = NOW()
             WHERE device_id = $1 AND is_expired = false",
        )
        .bind(device_id)
        .execute(db)
        .await?;
        tracing::info!(device_id = %device_id, "Soft-expired stale OTPK pool (replace_existing=true)");
    }

    // Insert classic pre-keys
    for prekey in prekeys {
        sqlx::query(
            r#"
            INSERT INTO one_time_prekeys (device_id, key_id, public_key)
            VALUES ($1, $2, $3)
            ON CONFLICT (device_id, key_id) DO NOTHING
            "#,
        )
        .bind(device_id)
        .bind(prekey.key_id as i32)
        .bind(&prekey.public_key)
        .execute(db)
        .await?;
    }

    // Insert Kyber OTPKs
    for kk in kyber_pre_keys {
        sqlx::query(
            r#"
            INSERT INTO kyber_one_time_pre_keys
                (device_id, key_id, public_key, signature, created_at, hybrid_signature)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (device_id, key_id) DO NOTHING
            "#,
        )
        .bind(device_id)
        .bind(kk.key_id as i32)
        .bind(&kk.public_key)
        .bind(&kk.signature)
        .bind(kk.created_at as i64)
        .bind(&kk.hybrid_signature)
        .execute(db)
        .await?;
    }

    // Return active counts
    let classic_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM one_time_prekeys WHERE device_id = $1 AND is_expired = false",
    )
    .bind(device_id)
    .fetch_one(db)
    .await?;

    let kyber_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM kyber_one_time_pre_keys WHERE device_id = $1 AND is_expired = false",
    )
    .bind(device_id)
    .fetch_one(db)
    .await?;

    construct_metrics::OTPK_UPLOADED_TOTAL.inc_by(prekeys.len() as u64);

    Ok((classic_count as u32, kyber_count as u32))
}

/// Get count of remaining one-time pre-keys
/// Whether `device_id` is an active device of `user_id`.
///
/// Used to detect a self bundle fetch, which must never burn one of the caller's own
/// one-time pre-keys (`resolve_otpk_consumption`). Returns `false` for an unknown or
/// deactivated device, and for a device whose `user_id` is still NULL (pre-migration
/// registration) — both are "not provably self", which is the safe answer here.
pub async fn device_belongs_to_user(db: &PgPool, device_id: &str, user_id: &str) -> Result<bool> {
    let Ok(uid) = uuid::Uuid::parse_str(user_id) else {
        return Ok(false);
    };
    let owns: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM devices
             WHERE device_id = $1 AND user_id = $2 AND is_active = true
         )",
    )
    .bind(device_id)
    .bind(uid)
    .fetch_one(db)
    .await?;
    Ok(owns)
}

pub async fn get_prekey_count(db: &PgPool, device_id: &str) -> Result<(u32, DateTime<Utc>)> {
    let row = sqlx::query_as::<_, PreKeyCountRow>(
        r#"
        SELECT COUNT(*) as count, MAX(uploaded_at) as last_upload
        FROM one_time_prekeys
        WHERE device_id = $1
          AND is_expired = false
        "#,
    )
    .bind(device_id)
    .fetch_one(db)
    .await?;

    Ok((
        row.count.unwrap_or(0) as u32,
        row.last_upload.unwrap_or_else(Utc::now),
    ))
}

/// Upload or replace the Kyber signed pre-key for a device.
/// Checked by [`check_kyber_prekey_v2`] before writing: 1568 bytes, a signed `created_at` no
/// older than `KYBER_SPK_MAX_AGE_SECS`, the Ed25519 signature over the v2 sign-message.
pub async fn upload_kyber_signed_prekey(
    db: &PgPool,
    device_id: &str,
    key_id: u32,
    public_key: &[u8],
    signature: &[u8],
    created_at: u64,
    // Optional hybrid (ML-DSA) signature over the same v2 sign-message. When provided it is
    // verified against the device's hybrid identity key and stored ATOMICALLY with the rotated
    // Kyber SPK. None preserves the legacy clear-and-re-set-separately behaviour.
    hybrid_sig: Option<&[u8]>,
) -> Result<u32> {
    let (verifying_key, hybrid_identity_key): (Vec<u8>, Option<Vec<u8>>) = sqlx::query_as(
        "SELECT verifying_key, hybrid_identity_key FROM devices WHERE device_id = $1 AND is_active = true",
    )
    .bind(device_id)
    .fetch_one(db)
    .await
    .map_err(|_| anyhow::anyhow!("Failed to fetch device verifying key"))?;

    check_kyber_prekey_v2(
        &verifying_key,
        public_key,
        created_at,
        signature,
        now_secs(),
        Some(KYBER_SPK_MAX_AGE_SECS),
    )?;

    // Verify the hybrid Kyber SPK signature now so it can be written in the same UPDATE (atomic).
    if let Some(sig) = hybrid_sig {
        check_kyber_prekey_hybrid_v2(hybrid_identity_key.as_deref(), public_key, created_at, sig)?;
    }

    let new_epoch: i32 = sqlx::query_scalar(
        r#"
        UPDATE devices
        SET kyber_signed_pre_key           = $2,
            kyber_signed_pre_key_id        = $3,
            kyber_signed_pre_key_signature = $4,
            -- Atomic with rotation: store the verified hybrid signature when sent ($5), else clear.
            kyber_signed_pre_key_hybrid_signature = $5,
            kyber_signed_pre_key_created_at = $6,
            key_updated_at                 = NOW(),
            kyber_spk_uploaded_at          = NOW(),
            kyber_spk_rotation_epoch       = COALESCE(kyber_spk_rotation_epoch, 0) + 1
        WHERE device_id = $1 AND is_active = true
        RETURNING kyber_spk_rotation_epoch
        "#,
    )
    .bind(device_id)
    .bind(public_key)
    .bind(key_id as i32)
    .bind(signature)
    .bind(hybrid_sig)
    .bind(created_at as i64)
    .fetch_one(db)
    .await?;

    Ok(new_epoch as u32)
}

// ============================================================================
// Hybrid PQ Identity (Ed25519 + ML-DSA-65) — migration 053
// ============================================================================

/// Domain-separation prologue for the Ed25519 cross-signature that binds a
/// device's hybrid identity key to its existing Ed25519 identity.
/// The cross-signed message is `HYBRID_ID_BIND_PROLOGUE || hybrid_identity_key`.
/// The client MUST sign the identical bytes with its device identity key.
const HYBRID_ID_BIND_PROLOGUE: &[u8] = b"KonstruktHybridId-v1";

/// Fields a client publishes (via UploadPreKeys) to register its hybrid PQ identity.
pub struct HybridIdentityUpload {
    /// Hybrid identity public key, 1984 bytes (required).
    pub hybrid_identity_key: Vec<u8>,
    /// Ed25519 cross-signature over the bind-message, 64 bytes (required).
    pub hybrid_identity_signature: Vec<u8>,
    /// Optional hybrid signature over the current SPK X3DH sign-message, 3373 bytes.
    pub signed_prekey_hybrid_signature: Option<Vec<u8>>,
    /// Optional hybrid signature over the current Kyber SPK X3DH sign-message, 3373 bytes.
    pub kyber_pre_key_hybrid_signature: Option<Vec<u8>>,
}

/// Verify the Ed25519 cross-signature binding `hybrid_identity_key` to the device's
/// existing Ed25519 identity (`verifying_key`). There is no `[0..32]` key-reuse
/// invariant: the hybrid key's Ed25519 half is independent and the binding is the
/// cross-signature alone.
fn verify_hybrid_identity_crosssign(
    verifying_key_bytes: &[u8],
    hybrid_identity_key: &[u8],
    cross_signature: &[u8],
) -> Result<()> {
    let vk_array: [u8; 32] = verifying_key_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("verifying_key must be 32 bytes"))?;
    let vk = VerifyingKey::from_bytes(&vk_array)
        .map_err(|e| anyhow::anyhow!("Invalid verifying key: {}", e))?;

    let sig_array: [u8; 64] = cross_signature
        .try_into()
        .map_err(|_| anyhow::anyhow!("hybrid_identity_signature must be 64 bytes"))?;
    let sig = Signature::from_bytes(&sig_array);

    let mut message = Vec::with_capacity(HYBRID_ID_BIND_PROLOGUE.len() + hybrid_identity_key.len());
    message.extend_from_slice(HYBRID_ID_BIND_PROLOGUE);
    message.extend_from_slice(hybrid_identity_key);

    vk.verify(&message, &sig)
        .map_err(|_| anyhow::anyhow!("Hybrid identity cross-signature verification failed"))
}

/// Verify and persist a device's hybrid PQ identity key and (optionally) the hybrid
/// signatures over its current signed pre-keys.
///
/// Capability-gated: only invoked when the client sends a `hybrid_identity_key`.
/// Verification performed before any write:
/// - `hybrid_identity_key` is exactly 1984 bytes;
/// - the Ed25519 cross-signature is valid under the device's `verifying_key`;
/// - if a SPK hybrid signature is present, it verifies against the CURRENT
///   `signed_prekey_public` under the hybrid key;
/// - if a Kyber SPK hybrid signature is present, it verifies against the CURRENT
///   `kyber_signed_pre_key` under the hybrid key.
///
/// Call AFTER any SPK / Kyber SPK rotation in the same request so the hybrid
/// signatures bind the freshly-stored prekeys (lockstep).
pub async fn store_hybrid_identity(
    db: &PgPool,
    device_id: &str,
    upload: &HybridIdentityUpload,
) -> Result<()> {
    if upload.hybrid_identity_key.len() != construct_crypto::pqc::HYBRID_SIG_PUBLIC_KEY_SIZE {
        anyhow::bail!(
            "Invalid hybrid_identity_key size: expected {} bytes, got {}",
            construct_crypto::pqc::HYBRID_SIG_PUBLIC_KEY_SIZE,
            upload.hybrid_identity_key.len()
        );
    }
    validate_ed25519_signature(&upload.hybrid_identity_signature)?;

    // Fetch the device's Ed25519 identity and current signed pre-keys for verification.
    let row = sqlx::query_as::<_, HybridVerifyRow>(
        r#"
        SELECT verifying_key, signed_prekey_public, kyber_signed_pre_key,
               kyber_signed_pre_key_created_at
        FROM devices
        WHERE device_id = $1 AND is_active = true
        "#,
    )
    .bind(device_id)
    .fetch_optional(db)
    .await?
    .ok_or_else(|| anyhow::anyhow!("Device not found or inactive: {}", device_id))?;

    // 1. Cross-signature binds the hybrid key to the device identity.
    verify_hybrid_identity_crosssign(
        &row.verifying_key,
        &upload.hybrid_identity_key,
        &upload.hybrid_identity_signature,
    )?;

    // 2. SPK hybrid signature (over the current classic SPK), if present.
    //
    // This signature is OPTIONAL and verified BEST-EFFORT. It is checked against the SPK the
    // server currently stores (`row.signed_prekey_public`); that can legitimately mismatch the
    // SPK the client signed over when the device's SPK is momentarily desynced from the server
    // (e.g. an SPK rotation whose RPC previously failed). Rejecting the whole upload in that case
    // is a DEADLOCK: the hybrid identity update (which is what SPK rotation later verifies its new
    // signature against) can never land, so the SPK can never re-sync, so the hybrid SPK signature
    // can never verify. Instead: verify best-effort, and on failure skip persisting THIS signature
    // while still updating the hybrid identity key — which the cross-signature above already bound
    // to the device. Once the identity is stored, a normal SPK rotation re-syncs the SPK and
    // re-attaches a fresh, verifying hybrid SPK signature. (A malformed/oversized signature is
    // still skipped, never persisted.) See otpk-session-init-deadlock (SPK↔hybrid deadlock).
    let spk_hybrid_sig_to_persist: Option<&[u8]> = match &upload.signed_prekey_hybrid_signature {
        Some(sig) if validate_hybrid_signature(sig).is_ok() => {
            let message =
                construct_crypto::pqc::build_prekey_sign_message(0x01, &row.signed_prekey_public);
            match construct_crypto::pqc::verify_hybrid_signature(
                &upload.hybrid_identity_key,
                &message,
                sig,
            ) {
                Ok(()) => Some(sig.as_slice()),
                Err(e) => {
                    tracing::warn!(
                        device_id = %device_id,
                        error = %e,
                        "SPK hybrid signature did not verify over the stored SPK (likely SPK \
                         desync) — accepting the hybrid identity update and skipping this \
                         signature so the device can re-sync its SPK and re-attach"
                    );
                    None
                }
            }
        }
        Some(_) => {
            tracing::warn!(device_id = %device_id, "malformed SPK hybrid signature — skipping");
            None
        }
        None => None,
    };

    // 3. Kyber SPK hybrid signature (over the current Kyber SPK), if present. Same best-effort
    //    treatment as the classic SPK signature above.
    let kyber_hybrid_sig_to_persist: Option<&[u8]> = match &upload.kyber_pre_key_hybrid_signature {
        Some(sig) if validate_hybrid_signature(sig).is_ok() => {
            match (
                row.kyber_signed_pre_key.as_ref(),
                row.kyber_signed_pre_key_created_at,
            ) {
                (Some(kyber), Some(created_at))
                    if construct_crypto::pqc::verify_hybrid_kyber_prekey_signature_v2(
                        &upload.hybrid_identity_key,
                        created_at.max(0) as u64,
                        kyber,
                        sig,
                    )
                    .is_ok() =>
                {
                    Some(sig.as_slice())
                }
                _ => {
                    tracing::warn!(
                        device_id = %device_id,
                        "Kyber SPK hybrid signature did not verify over the stored Kyber SPK \
                         (or no Kyber SPK stored) — accepting hybrid identity, skipping it"
                    );
                    None
                }
            }
        }
        Some(_) => {
            tracing::warn!(device_id = %device_id, "malformed Kyber SPK hybrid signature — skipping");
            None
        }
        None => None,
    };

    // Persist. The hybrid identity key + cross-signature are always updated (the cross-signature
    // was verified against the device identity above).
    //
    // The prekey hybrid signatures are written OUTRIGHT (not COALESCE'd): a stored SPK hybrid
    // signature is only meaningful relative to a specific (hybrid_identity_key, signed_prekey)
    // pair, and we are advancing hybrid_identity_key here — so any previously-stored signature
    // (whether set by an earlier hybrid publish or by store_signed_prekey) is now under the OLD
    // hybrid key and is therefore STALE. Keeping it (the old COALESCE behaviour) served a
    // self-inconsistent bundle {new hybrid_key, old spkSig} that every peer hard-rejects as
    // "SPK hybrid signature invalid" and can never recover from (build 496 regression). So when
    // the upload's signature doesn't verify over the stored SPK ($4/$5 → NULL), we NULL the
    // column: the bundle is then honestly "hybrid identity present, SPK not yet hybrid-signed",
    // which a peer can degrade on (classic SPK signature) instead of hard-blocking. A subsequent
    // SPK rotation re-attaches a fresh, verifying signature. See otpk-session-init-deadlock.
    sqlx::query(
        r#"
        UPDATE devices
        SET hybrid_identity_key       = $2,
            hybrid_identity_signature = $3,
            signed_prekey_hybrid_signature        = $4,
            kyber_signed_pre_key_hybrid_signature = $5
        WHERE device_id = $1 AND is_active = true
        "#,
    )
    .bind(device_id)
    .bind(&upload.hybrid_identity_key)
    .bind(&upload.hybrid_identity_signature)
    .bind(spk_hybrid_sig_to_persist)
    .bind(kyber_hybrid_sig_to_persist)
    .execute(db)
    .await?;

    Ok(())
}

/// Persist the client's declaration of PQ_RATCHET support (SuiteID=3 capability).
/// Called from UploadPreKeys handler. This flag is then served in PreKeyBundles
/// so that peers can negotiate Suite 3 sessions (sparse continuous ratchet, no OTPK after bootstrap).
pub async fn set_device_supports_pq_ratchet(
    db: &PgPool,
    device_id: &str,
    supports: bool,
) -> Result<()> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM devices WHERE device_id = $1 AND is_active = true)",
    )
    .bind(device_id)
    .fetch_one(db)
    .await?;

    if !exists {
        anyhow::bail!("Device not found or inactive");
    }

    sqlx::query(
        "UPDATE devices SET supports_pq_ratchet = $2, key_updated_at = NOW() WHERE device_id = $1 AND is_active = true",
    )
    .bind(device_id)
    .bind(supports)
    .execute(db)
    .await?;

    Ok(())
}

// ============================================================================
// Signed Pre-Key Operations
// ============================================================================

/// Rotate signed pre-key (archive old one)
pub async fn rotate_signed_prekey(
    db: &PgPool,
    device_id: &str,
    new_key: &SignedPreKey,
    reason: &str,
    // Optional hybrid (ML-DSA) signature over new_key.public_key (suite 0x01). When provided it
    // is verified against the device's hybrid identity key and stored ATOMICALLY with the rotated
    // SPK (same UPDATE), so the bundle is never served with a hybrid identity but an unsigned SPK.
    // None preserves the legacy behaviour (clear the column; the caller re-sets it via a separate
    // UploadPreKeys/store_hybrid_identity call).
    spk_hybrid_sig: Option<&[u8]>,
) -> Result<(DateTime<Utc>, u32)> {
    // Verify Classic SPK signature before archiving or updating.
    // Kyber SPK is verified in upload_kyber_signed_prekey via check_kyber_prekey_v2 (0x11).
    // suite_id 0x01 = ClassicX25519 (see verify_prekey_signature header comment).
    let (verifying_key_bytes, hybrid_identity_key): (Vec<u8>, Option<Vec<u8>>) =
        sqlx::query_as(
            "SELECT verifying_key, hybrid_identity_key FROM devices WHERE device_id = $1 AND is_active = true",
        )
        .bind(device_id)
        .fetch_optional(db)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Device not found or inactive: {}", device_id))?;

    verify_prekey_signature(
        &verifying_key_bytes,
        0x01,
        &new_key.public_key,
        &new_key.signature,
    )
    .map_err(|e| anyhow::anyhow!("Classic SPK signature verification failed: {}", e))?;

    // If a hybrid SPK signature is provided, verify it over the NEW SPK now so it can be written
    // in the same UPDATE below (atomic rotation — no NULL/unsigned window).
    if let Some(sig) = spk_hybrid_sig {
        validate_hybrid_signature(sig)?;
        let hybrid_key = hybrid_identity_key.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "signed_pre_key_hybrid_signature provided but device has no hybrid identity key"
            )
        })?;
        let message = construct_crypto::pqc::build_prekey_sign_message(0x01, &new_key.public_key);
        construct_crypto::pqc::verify_hybrid_signature(hybrid_key, &message, sig)
            .map_err(|e| anyhow::anyhow!("SPK hybrid signature verification failed: {}", e))?;
    }

    // Get current signed prekey (including its ID) before updating
    let current = sqlx::query_as::<_, SignedPreKeyRow>(
        r#"
        SELECT signed_prekey_id, signed_prekey_public, signed_prekey_signature
        FROM devices
        WHERE device_id = $1 AND is_active = true
        "#,
    )
    .bind(device_id)
    .fetch_optional(db)
    .await?;

    // Archive old key with its real key_id
    if let Some(old) = current
        && let Some(sig) = old.signed_prekey_signature
    {
        sqlx::query(
                r#"
                INSERT INTO signed_prekey_archive (device_id, key_id, public_key, signature, rotation_reason)
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT (device_id, key_id) DO UPDATE SET
                    public_key = $3, signature = $4, rotation_reason = $5,
                    archived_at = NOW(), expires_at = NOW() + INTERVAL '48 hours'
                "#,
            )
            .bind(device_id)
            .bind(old.signed_prekey_id)
            .bind(&old.signed_prekey_public)
            .bind(&sig)
            .bind(reason)
            .execute(db)
            .await?;
    }

    // Update device with new signed prekey, upload timestamp, and incremented epoch
    let new_epoch: i32 = sqlx::query_scalar(
        r#"
        UPDATE devices
        SET signed_prekey_public = $2,
            signed_prekey_id = $3,
            signed_prekey_signature = $4,
            -- Atomic with rotation: store the verified hybrid signature when the client sent it
            -- ($5), otherwise clear it ($5 = NULL) for the caller to re-set via store_hybrid_identity.
            signed_prekey_hybrid_signature = $5,
            key_updated_at = NOW(),
            spk_uploaded_at = NOW(),
            spk_rotation_epoch = COALESCE(spk_rotation_epoch, 0) + 1
        WHERE device_id = $1
        RETURNING spk_rotation_epoch
        "#,
    )
    .bind(device_id)
    .bind(&new_key.public_key)
    .bind(new_key.key_id as i32)
    .bind(&new_key.signature)
    .bind(spk_hybrid_sig)
    .fetch_one(db)
    .await?;

    // Old key valid until (48 hours — aligns with signed_prekey_archive expires_at)
    let expires_at = Utc::now() + chrono::Duration::hours(48);
    Ok((expires_at, new_epoch as u32))
}

/// Get signed pre-key age
pub async fn get_signed_prekey_age(
    db: &PgPool,
    device_id: &str,
) -> Result<Option<(u32, DateTime<Utc>, bool)>> {
    let row = sqlx::query_as::<_, SignedPreKeyAgeRow>(
        r#"
        SELECT signed_prekey_id, key_updated_at, registered_at
        FROM devices
        WHERE device_id = $1 AND is_active = true
        "#,
    )
    .bind(device_id)
    .fetch_optional(db)
    .await?;

    match row {
        Some(r) => {
            let uploaded_at = r.key_updated_at.unwrap_or(r.registered_at);
            let age = Utc::now() - uploaded_at;
            let should_rotate = age.num_days() >= 30;
            Ok(Some((
                r.signed_prekey_id as u32,
                uploaded_at,
                should_rotate,
            )))
        }
        None => Ok(None),
    }
}

// ============================================================================
// Identity Key Operations
// ============================================================================

/// Get identity key for a user/device
pub async fn get_identity_key(
    db: &PgPool,
    user_id: &str,
    device_id: Option<&str>,
) -> Result<Option<(Vec<u8>, DateTime<Utc>)>> {
    let row = if let Some(did) = device_id {
        sqlx::query_as::<_, IdentityKeyRow>(
            r#"
            SELECT identity_public, registered_at
            FROM devices
            WHERE device_id = $1 AND user_id = $2::uuid AND is_active = true
            "#,
        )
        .bind(did)
        .bind(user_id)
        .fetch_optional(db)
        .await?
    } else {
        sqlx::query_as::<_, IdentityKeyRow>(
            r#"
            SELECT identity_public, registered_at
            FROM devices
            WHERE user_id = $1::uuid AND is_active = true
            ORDER BY registered_at ASC
            LIMIT 1
            "#,
        )
        .bind(user_id)
        .fetch_optional(db)
        .await?
    };

    Ok(row.map(|r| (r.identity_public, r.registered_at)))
}

/// Calculate safety number from two identity keys
pub fn calculate_safety_number(
    our_key: &[u8],
    their_key: &[u8],
    our_id: &str,
    their_id: &str,
) -> String {
    use sha2::{Digest, Sha256};

    // Determine order (lexicographically smaller ID first)
    let (first_key, first_id, second_key, second_id) = if our_id < their_id {
        (our_key, our_id, their_key, their_id)
    } else {
        (their_key, their_id, our_key, our_id)
    };

    // Hash: version || id1 || key1 || id2 || key2
    let mut hasher = Sha256::new();
    hasher.update(b"\x00"); // version byte
    hasher.update(first_id.as_bytes());
    hasher.update(first_key);
    hasher.update(second_id.as_bytes());
    hasher.update(second_key);

    let hash = hasher.finalize();

    // Convert to 60-digit number (5 groups of 12 digits)
    // Use first 30 bytes, convert each 5 bytes to 12-digit group
    let mut result = String::with_capacity(65);
    for i in 0..5 {
        let offset = i * 5;
        let value = u64::from_be_bytes([
            0,
            0,
            0,
            hash[offset],
            hash[offset + 1],
            hash[offset + 2],
            hash[offset + 3],
            hash[offset + 4],
        ]) % 1_000_000_000_000;

        if i > 0 {
            result.push(' ');
        }
        result.push_str(&format!("{:012}", value));
    }

    result
}

// ============================================================================
// Row Types
// ============================================================================

#[derive(sqlx::FromRow)]
struct DeviceRow {
    device_id: String,
    identity_public: Vec<u8>,
    verifying_key: Vec<u8>,
    signed_prekey_public: Vec<u8>,
    signed_prekey_id: i32,
    signed_prekey_signature: Option<Vec<u8>>,
    crypto_suite: String,
    registered_at: DateTime<Utc>,
    // Kyber SPK columns (nullable, added in migration 028)
    kyber_signed_pre_key: Option<Vec<u8>>,
    kyber_signed_pre_key_id: Option<i32>,
    kyber_signed_pre_key_signature: Option<Vec<u8>>,
    // Signed creation time of the Kyber SPK (migration 071)
    kyber_signed_pre_key_created_at: Option<i64>,
    // SPK timestamp and epoch columns (nullable, added in migration 031)
    spk_uploaded_at: Option<DateTime<Utc>>,
    spk_rotation_epoch: i32,
    kyber_spk_uploaded_at: Option<DateTime<Utc>>,
    kyber_spk_rotation_epoch: i32,
    // Hybrid PQ identity columns (nullable, added in migration 053)
    hybrid_identity_key: Option<Vec<u8>>,
    hybrid_identity_signature: Option<Vec<u8>>,
    signed_prekey_hybrid_signature: Option<Vec<u8>>,
    kyber_signed_pre_key_hybrid_signature: Option<Vec<u8>>,

    // PQ ratchet capability (additive, for Suite 3)
    supports_pq_ratchet: bool,
}

#[derive(sqlx::FromRow)]
struct OneTimePreKeyRow {
    key_id: i32,
    public_key: Vec<u8>,
}

#[derive(sqlx::FromRow)]
struct KyberOneTimePreKeyRow {
    key_id: i32,
    public_key: Vec<u8>,
    signature: Vec<u8>,
    // Migration 071. Nullable in the schema; every row written since carries both.
    created_at: Option<i64>,
    hybrid_signature: Option<Vec<u8>>,
}

#[derive(sqlx::FromRow)]
struct PreKeyCountRow {
    count: Option<i64>,
    last_upload: Option<DateTime<Utc>>,
}

#[derive(sqlx::FromRow)]
struct SignedPreKeyRow {
    signed_prekey_id: i32,
    signed_prekey_public: Vec<u8>,
    signed_prekey_signature: Option<Vec<u8>>,
}

/// Row used by `store_hybrid_identity` to verify hybrid signatures against the
/// device's current Ed25519 identity and signed pre-keys.
#[derive(sqlx::FromRow)]
struct HybridVerifyRow {
    verifying_key: Vec<u8>,
    signed_prekey_public: Vec<u8>,
    kyber_signed_pre_key: Option<Vec<u8>>,
    kyber_signed_pre_key_created_at: Option<i64>,
}

#[derive(sqlx::FromRow)]
struct SignedPreKeyAgeRow {
    signed_prekey_id: i32,
    key_updated_at: Option<DateTime<Utc>>,
    registered_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct IdentityKeyRow {
    identity_public: Vec<u8>,
    registered_at: DateTime<Utc>,
}

// ============================================================================
// Cleanup Jobs
// ============================================================================

/// Delete expired archived signed pre-keys
#[allow(dead_code)]
pub async fn cleanup_expired_archives(db: &PgPool) -> Result<u64> {
    let result = sqlx::query("DELETE FROM signed_prekey_archive WHERE expires_at < NOW()")
        .execute(db)
        .await?;
    Ok(result.rows_affected())
}

/// Hard-delete OTPKs that were soft-expired more than 48 hours ago.
///
/// Fleet-wide one-time pre-key inventory, for metrics.
///
/// Counts devices, not keys. A total key count would be dominated by whichever
/// device last uploaded a hundred of them and would say nothing about whether
/// anyone can still start a session; the number that matters is how many
/// devices are at zero, because a peer contacting one of those gets an SPK-only
/// bundle — the session still forms, but without the one-time key, and neither
/// user is told.
///
/// The LEFT JOIN is load-bearing: a device with no rows in `one_time_prekeys` at
/// all is exactly the exhausted case, and an inner join would silently drop
/// precisely the devices being counted.
pub struct OtpkInventory {
    pub devices: i64,
    pub low: i64,
    pub exhausted: i64,
}

pub const OTPK_LOW_WATER_MARK: i64 = 10;

pub async fn otpk_inventory(db: &PgPool) -> Result<OtpkInventory> {
    let row: (i64, i64, i64) = sqlx::query_as(
        r#"
        SELECT count(*),
               count(*) FILTER (WHERE n < $1),
               count(*) FILTER (WHERE n = 0)
        FROM (
            SELECT d.device_id, count(o.key_id) AS n
            FROM devices d
            LEFT JOIN one_time_prekeys o
              ON o.device_id = d.device_id AND o.is_expired = false
            WHERE d.is_active = true
            GROUP BY d.device_id
        ) t
        "#,
    )
    .bind(OTPK_LOW_WATER_MARK)
    .fetch_one(db)
    .await?;

    Ok(OtpkInventory {
        devices: row.0,
        low: row.1,
        exhausted: row.2,
    })
}

/// Called on a schedule (e.g. every hour). The 48-hour window matches
/// `signed_prekey_archive` and gives in-flight prekey messages time to arrive.
#[allow(dead_code)]
pub async fn cleanup_expired_otpks(db: &PgPool) -> Result<u64> {
    let result = sqlx::query(
        "DELETE FROM one_time_prekeys
         WHERE is_expired = true
           AND expired_at < NOW() - INTERVAL '48 hours'",
    )
    .execute(db)
    .await?;
    Ok(result.rows_affected())
}

/// Hard-delete Kyber OTPKs that were soft-expired more than 48 hours ago.
/// Same retention policy as classic OTPKs.
#[allow(dead_code)]
pub async fn cleanup_expired_kyber_otpks(db: &PgPool) -> Result<u64> {
    let result = sqlx::query(
        "DELETE FROM kyber_one_time_pre_keys
         WHERE is_expired = true
           AND expired_at < NOW() - INTERVAL '48 hours'",
    )
    .execute(db)
    .await?;
    Ok(result.rows_affected())
}

// ============================================================================
// Unit Tests
// ============================================================================
//
// Tests marked #[ignore] require a running PostgreSQL instance.
// Run all: cargo test --package key-service
// Run DB tests: cargo test --package key-service -- --ignored
// Run DB tests with real DB: DATABASE_URL=postgres://... cargo test --package key-service -- --ignored
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helpers ──────────────────────────────────────────────────────────────

    #[derive(Debug, Clone)]
    struct TestPreKey {
        key_id: u32,
        public_key: Vec<u8>,
    }

    impl From<TestPreKey> for OneTimePreKey {
        fn from(k: TestPreKey) -> Self {
            OneTimePreKey {
                key_id: k.key_id,
                public_key: k.public_key,
            }
        }
    }

    fn make_prekeys(n: u32) -> Vec<OneTimePreKey> {
        (1..=n)
            .map(|i| OneTimePreKey {
                key_id: i,
                public_key: vec![i as u8; 32],
            })
            .collect()
    }

    // ── Pure logic tests (no DB) ──────────────────────────────────────────────

    #[test]
    fn test_prekey_batch_not_empty() {
        let keys = make_prekeys(10);
        assert_eq!(keys.len(), 10);
        assert_eq!(keys[0].key_id, 1);
        assert_eq!(keys[9].key_id, 10);
    }

    // ── PQC validation tests (no DB) ─────────────────────────────────────────

    #[test]
    fn test_validate_kyber_public_key_correct_size_accepted() {
        let key = vec![0xAB_u8; KYBER_PUBLIC_KEY_SIZE]; // exactly 1568 bytes
        assert!(validate_kyber_public_key(&key).is_ok());
    }

    #[test]
    fn test_validate_kyber_public_key_wrong_size_rejected() {
        let short = vec![0u8; 32]; // X25519 size — must be rejected
        let err = validate_kyber_public_key(&short).unwrap_err();
        assert!(
            err.to_string().contains("1568"),
            "error must mention expected size"
        );

        // The ML-KEM-768 size every pre-v2 client uploaded: no longer a Kyber key here.
        let ml_kem_768 = vec![0u8; 1184];
        assert!(validate_kyber_public_key(&ml_kem_768).is_err());

        assert!(validate_kyber_public_key(&[]).is_err());
    }

    #[test]
    fn test_validate_ed25519_signature_correct_size_accepted() {
        let sig = vec![0xFF_u8; ED25519_SIGNATURE_SIZE]; // exactly 64 bytes
        assert!(validate_ed25519_signature(&sig).is_ok());
    }

    #[test]
    fn test_validate_ed25519_signature_wrong_size_rejected() {
        assert!(validate_ed25519_signature(&[0u8; 32]).is_err()); // too short
        assert!(validate_ed25519_signature(&[0u8; 65]).is_err()); // too long
        assert!(validate_ed25519_signature(&[]).is_err());
    }

    #[test]
    fn test_kyber_public_key_size_constant() {
        // FIPS 203: an ML-KEM-1024 encapsulation key is 1568 bytes, as is its ciphertext.
        assert_eq!(KYBER_PUBLIC_KEY_SIZE, 1568);
        assert_eq!(KYBER_CIPHERTEXT_SIZE, 1568);
        assert_eq!(ED25519_SIGNATURE_SIZE, 64);
    }

    // ── PQXDH v2 Kyber prekey checks (no DB) ─────────────────────────────────

    const NOW: u64 = 1_800_000_000;

    /// A device as a PQXDH v2 core signs its keys: Ed25519 identity plus hybrid identity.
    struct SigningDevice {
        ed25519: SigningKey,
        hybrid_sk: Vec<u8>,
        hybrid_pk: Vec<u8>,
    }

    impl SigningDevice {
        fn new() -> Self {
            let (hybrid_sk, hybrid_pk) = construct_crypto::pqc::generate_hybrid_signature_keypair();
            Self {
                ed25519: SigningKey::from_bytes(&[9u8; 32]),
                hybrid_sk,
                hybrid_pk,
            }
        }

        fn verifying_key(&self) -> Vec<u8> {
            self.ed25519.verifying_key().to_bytes().to_vec()
        }

        fn kyber_key(&self, key_id: u32, created_at: u64) -> KyberOneTimePreKey {
            let public_key = vec![key_id as u8; KYBER_PUBLIC_KEY_SIZE];
            let message =
                construct_crypto::pqc::build_kyber_prekey_sign_message_v2(created_at, &public_key);
            KyberOneTimePreKey {
                key_id,
                signature: self.ed25519.sign(&message).to_bytes().to_vec(),
                hybrid_signature: construct_crypto::pqc::hybrid_sign(&self.hybrid_sk, &message)
                    .unwrap(),
                public_key,
                created_at,
            }
        }
    }

    fn check(device: &SigningDevice, k: &KyberOneTimePreKey, max_age: Option<u64>) -> Result<()> {
        check_kyber_prekey_v2(
            &device.verifying_key(),
            &k.public_key,
            k.created_at,
            &k.signature,
            NOW,
            max_age,
        )
    }

    #[test]
    fn test_a_v2_kyber_prekey_passes_both_checks() {
        let device = SigningDevice::new();
        let k = device.kyber_key(1, NOW - 3600);
        check(&device, &k, Some(KYBER_SPK_MAX_AGE_SECS)).unwrap();
        check_kyber_prekey_hybrid_v2(
            Some(&device.hybrid_pk),
            &k.public_key,
            k.created_at,
            &k.hybrid_signature,
        )
        .unwrap();
    }

    /// The server cannot move a key's time: `created_at` is under both signatures.
    #[test]
    fn test_a_changed_created_at_breaks_both_signatures() {
        let device = SigningDevice::new();
        let mut k = device.kyber_key(1, NOW - 3600);
        k.created_at += 1;
        assert!(check(&device, &k, None).is_err());
        assert!(
            check_kyber_prekey_hybrid_v2(
                Some(&device.hybrid_pk),
                &k.public_key,
                k.created_at,
                &k.hybrid_signature
            )
            .is_err()
        );
    }

    #[test]
    fn test_a_v1_kyber_signature_is_refused() {
        let device = SigningDevice::new();
        let mut k = device.kyber_key(1, NOW - 3600);
        let v1 = construct_crypto::pqc::build_prekey_sign_message(0x10, &k.public_key);
        k.signature = device.ed25519.sign(&v1).to_bytes().to_vec();
        assert!(check(&device, &k, None).is_err());
    }

    #[test]
    fn test_kyber_prekey_times_are_checked() {
        let device = SigningDevice::new();
        // No time at all: a pre-v2 upload.
        assert!(check(&device, &device.kyber_key(1, 0), None).is_err());
        // Too far ahead of the server clock.
        let ahead = device.kyber_key(1, NOW + KYBER_CREATED_AT_MAX_SKEW_SECS + 1);
        assert!(check(&device, &ahead, None).is_err());
        // A signed pre-key older than an initiator accepts; a one-time key of that age is fine.
        let old = device.kyber_key(1, NOW - KYBER_SPK_MAX_AGE_SECS - 1);
        assert!(check(&device, &old, Some(KYBER_SPK_MAX_AGE_SECS)).is_err());
        check(&device, &old, None).unwrap();
    }

    #[test]
    fn test_a_kyber_prekey_hybrid_signature_needs_a_hybrid_identity() {
        let device = SigningDevice::new();
        let k = device.kyber_key(1, NOW);
        assert!(
            check_kyber_prekey_hybrid_v2(None, &k.public_key, k.created_at, &k.hybrid_signature)
                .is_err()
        );
        let (_, other) = construct_crypto::pqc::generate_hybrid_signature_keypair();
        assert!(
            check_kyber_prekey_hybrid_v2(
                Some(&other),
                &k.public_key,
                k.created_at,
                &k.hybrid_signature
            )
            .is_err()
        );
    }

    // ── Hybrid PQ identity cross-signature (no DB) ───────────────────────────

    /// Build (device_verifying_key, hybrid_public_key, cross_signature) where the
    /// device Ed25519 identity cross-signs the bind-message over the hybrid key.
    fn make_crosssigned_hybrid() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let device = SigningKey::from_bytes(&[7u8; 32]);
        let verifying_key = device.verifying_key().to_bytes().to_vec();
        let (_hybrid_sk, hybrid_pk) = construct_crypto::pqc::generate_hybrid_signature_keypair();
        let mut message = Vec::new();
        message.extend_from_slice(HYBRID_ID_BIND_PROLOGUE);
        message.extend_from_slice(&hybrid_pk);
        let cross_sig = device.sign(&message).to_bytes().to_vec();
        (verifying_key, hybrid_pk, cross_sig)
    }

    #[test]
    fn test_hybrid_identity_crosssign_roundtrip() {
        let (vk, hk, sig) = make_crosssigned_hybrid();
        assert_eq!(hk.len(), construct_crypto::pqc::HYBRID_SIG_PUBLIC_KEY_SIZE);
        assert!(verify_hybrid_identity_crosssign(&vk, &hk, &sig).is_ok());
    }

    #[test]
    fn test_hybrid_identity_crosssign_rejects_wrong_device_key() {
        let (_vk, hk, sig) = make_crosssigned_hybrid();
        // A different device identity must not validate the cross-signature.
        let other_vk = SigningKey::from_bytes(&[9u8; 32])
            .verifying_key()
            .to_bytes()
            .to_vec();
        assert!(verify_hybrid_identity_crosssign(&other_vk, &hk, &sig).is_err());
    }

    #[test]
    fn test_hybrid_identity_crosssign_rejects_tampered_key() {
        let (vk, mut hk, sig) = make_crosssigned_hybrid();
        hk[0] ^= 0xFF; // flip a byte of the signed hybrid key
        assert!(verify_hybrid_identity_crosssign(&vk, &hk, &sig).is_err());
    }

    #[test]
    fn test_hybrid_identity_crosssign_rejects_bad_sizes() {
        let (vk, hk, sig) = make_crosssigned_hybrid();
        // Wrong verifying-key length.
        assert!(verify_hybrid_identity_crosssign(&vk[..31], &hk, &sig).is_err());
        // Wrong signature length.
        assert!(verify_hybrid_identity_crosssign(&vk, &hk, &sig[..63]).is_err());
    }

    // ── SPK wake-push threshold tests (no DB) ────────────────────────────────

    fn make_bundle_for_wake_test(
        spk_age_days: Option<f64>,
        kyber_spk_age_days: Option<f64>,
    ) -> PreKeyBundle {
        let now = Utc::now();
        PreKeyBundle {
            device_id: "test-device".into(),
            identity_key: vec![],
            verifying_key: vec![],
            signed_prekey: vec![],
            signed_prekey_id: 0,
            signed_prekey_signature: vec![],
            one_time_prekey: None,
            one_time_prekey_id: None,
            crypto_suite: "Curve25519+Ed25519".into(),
            registered_at: now,
            kyber_pre_key: None,
            kyber_pre_key_id: None,
            kyber_pre_key_signature: None,
            kyber_one_time_pre_key: None,
            kyber_one_time_pre_key_id: None,
            kyber_pre_key_created_at: None,
            kyber_one_time_pre_key_signature: None,
            kyber_one_time_pre_key_created_at: None,
            kyber_one_time_pre_key_hybrid_signature: None,
            spk_uploaded_at: spk_age_days.map(|d| now - chrono::Duration::days(d as i64)),
            spk_rotation_epoch: 0,
            kyber_spk_uploaded_at: kyber_spk_age_days
                .map(|d| now - chrono::Duration::days(d as i64)),
            kyber_spk_rotation_epoch: 0,
            bundle_signature: None,
            kt_proof: None,
            hybrid_identity_key: None,
            hybrid_identity_signature: None,
            signed_prekey_hybrid_signature: None,
            kyber_pre_key_hybrid_signature: None,
            hybrid_kt_proof: None,
            supports_pq_ratchet: false,
        }
    }

    #[test]
    fn test_spk_wake_fires_when_spk_age_exceeds_threshold() {
        let bundle = make_bundle_for_wake_test(Some(22.0), None);
        assert!(spk_is_stale_enough_for_wake(&bundle));
    }

    #[test]
    fn test_spk_wake_fires_when_kyber_spk_age_exceeds_threshold() {
        let bundle = make_bundle_for_wake_test(None, Some(22.0));
        assert!(spk_is_stale_enough_for_wake(&bundle));
    }

    #[test]
    fn test_spk_wake_does_not_fire_for_fresh_spk() {
        let bundle = make_bundle_for_wake_test(Some(5.0), None);
        assert!(!spk_is_stale_enough_for_wake(&bundle));
    }

    #[test]
    fn test_spk_wake_does_not_fire_for_no_timestamps() {
        let bundle = make_bundle_for_wake_test(None, None);
        assert!(!spk_is_stale_enough_for_wake(&bundle));
    }

    #[test]
    fn test_spk_wake_fires_when_either_spk_is_stale() {
        let bundle = make_bundle_for_wake_test(Some(5.0), Some(22.0));
        assert!(spk_is_stale_enough_for_wake(&bundle));
    }

    #[test]
    fn test_spk_wake_boundary_just_below_threshold() {
        let bundle = make_bundle_for_wake_test(Some(20.99), None);
        assert!(!spk_is_stale_enough_for_wake(&bundle));
    }

    // ── Database tests (require PostgreSQL) ──────────────────────────────────
    //
    // These tests are #[ignore] by default and must be run explicitly.
    // They require the construct DB schema to be migrated:
    //   DATABASE_URL=postgres://construct:password@localhost/construct \
    //   cargo test --package key-service -- --ignored

    async fn get_test_db() -> PgPool {
        let url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://construct:password@localhost/construct".to_string());
        sqlx::PgPool::connect(&url)
            .await
            .expect("Failed to connect to test DB")
    }

    async fn insert_test_device(db: &PgPool) -> String {
        let device_id = uuid::Uuid::new_v4().to_string();
        let user_id = uuid::Uuid::new_v4();
        sqlx::query(
            "INSERT INTO users (user_id, username, created_at) VALUES ($1, $2, NOW())
             ON CONFLICT DO NOTHING",
        )
        .bind(user_id)
        .bind(format!("testuser-{}", &device_id[..8]))
        .execute(db)
        .await
        .ok();
        sqlx::query(
            "INSERT INTO devices (device_id, user_id, is_active, created_at)
             VALUES ($1::uuid, $2, true, NOW())",
        )
        .bind(&device_id)
        .bind(user_id)
        .execute(db)
        .await
        .expect("Failed to insert test device");
        device_id
    }

    /// Like `insert_test_device` but also returns the owning user_id, for tests that
    /// need to reason about device↔user ownership.
    async fn insert_test_device_with_user(db: &PgPool) -> (String, uuid::Uuid) {
        let device_id = uuid::Uuid::new_v4().to_string();
        let user_id = uuid::Uuid::new_v4();
        sqlx::query(
            "INSERT INTO users (user_id, username, created_at) VALUES ($1, $2, NOW())
             ON CONFLICT DO NOTHING",
        )
        .bind(user_id)
        .bind(format!("testuser-{}", &device_id[..8]))
        .execute(db)
        .await
        .ok();
        sqlx::query(
            "INSERT INTO devices (device_id, user_id, is_active, created_at)
             VALUES ($1::uuid, $2, true, NOW())",
        )
        .bind(&device_id)
        .bind(user_id)
        .execute(db)
        .await
        .expect("Failed to insert test device");
        (device_id, user_id)
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn test_device_belongs_to_user_gates_self_fetch() {
        // Guards the rule that a bundle fetch of your OWN account must not burn one of
        // your own one-time pre-keys (see `resolve_otpk_consumption` in main.rs). A wrong
        // answer here either re-opens the self-drain or hands a stranger a free bundle.
        let db = get_test_db().await;
        let (device_a, user_a) = insert_test_device_with_user(&db).await;
        let (device_b, user_b) = insert_test_device_with_user(&db).await;

        assert!(
            device_belongs_to_user(&db, &device_a, &user_a.to_string())
                .await
                .unwrap(),
            "own device must be recognised as self"
        );
        assert!(
            !device_belongs_to_user(&db, &device_a, &user_b.to_string())
                .await
                .unwrap(),
            "another user's device must NOT count as self"
        );
        assert!(
            !device_belongs_to_user(&db, "not-a-device", &user_a.to_string())
                .await
                .unwrap(),
            "unknown device must not count as self"
        );
        assert!(
            !device_belongs_to_user(&db, &device_a, "not-a-uuid")
                .await
                .unwrap(),
            "malformed user_id must be rejected, not error out"
        );

        // A deactivated device must lose self status (revoked device shouldn't get the
        // non-consuming path either).
        sqlx::query("UPDATE devices SET is_active = false WHERE device_id = $1::uuid")
            .bind(&device_a)
            .execute(&db)
            .await
            .unwrap();
        assert!(
            !device_belongs_to_user(&db, &device_a, &user_a.to_string())
                .await
                .unwrap(),
            "deactivated device must not count as self"
        );

        cleanup_device(&db, &device_a).await;
        cleanup_device(&db, &device_b).await;
    }

    async fn cleanup_device(db: &PgPool, device_id: &str) {
        sqlx::query("DELETE FROM one_time_prekeys WHERE device_id = $1::uuid")
            .bind(device_id)
            .execute(db)
            .await
            .ok();
        sqlx::query("DELETE FROM devices WHERE device_id = $1::uuid")
            .bind(device_id)
            .execute(db)
            .await
            .ok();
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn test_upload_prekeys_replace_existing_soft_expires_old_keys() {
        let db = get_test_db().await;
        let device_id = insert_test_device(&db).await;

        // Upload initial batch of 10 keys
        let initial_keys = make_prekeys(10);
        upload_prekeys(&db, &device_id, &initial_keys, false, &[])
            .await
            .expect("Initial upload failed");

        // Verify 10 active keys exist
        let active_count: i64 =
            sqlx::query_scalar(
                "SELECT COUNT(*) FROM one_time_prekeys WHERE device_id = $1::uuid AND is_expired = false",
            )
            .bind(&device_id)
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(
            active_count, 10,
            "should have 10 active keys after initial upload"
        );

        // Upload 5 new keys with replace_existing=true
        let new_keys = (51..=55)
            .map(|i| OneTimePreKey {
                key_id: i,
                public_key: vec![i as u8; 32],
            })
            .collect::<Vec<_>>();
        upload_prekeys(&db, &device_id, &new_keys, true, &[])
            .await
            .expect("Replace upload failed");

        // Old keys must be soft-expired (is_expired=true), NOT hard-deleted
        let still_exist: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM one_time_prekeys WHERE device_id = $1::uuid AND is_expired = true AND key_id <= 10",
        )
        .bind(&device_id)
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(
            still_exist, 10,
            "old keys must be soft-expired, not hard-deleted"
        );

        // New keys must be active
        let new_active: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM one_time_prekeys WHERE device_id = $1::uuid AND is_expired = false AND key_id >= 51",
        )
        .bind(&device_id)
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(new_active, 5, "new keys must be active");

        cleanup_device(&db, &device_id).await;
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn test_upload_prekeys_no_replace_keeps_old_keys_active() {
        let db = get_test_db().await;
        let device_id = insert_test_device(&db).await;

        let initial_keys = make_prekeys(5);
        upload_prekeys(&db, &device_id, &initial_keys, false, &[])
            .await
            .unwrap();

        // Upload more without replace_existing
        let more_keys = (6..=8)
            .map(|i| OneTimePreKey {
                key_id: i,
                public_key: vec![i as u8; 32],
            })
            .collect::<Vec<_>>();
        upload_prekeys(&db, &device_id, &more_keys, false, &[])
            .await
            .unwrap();

        // All 8 keys should be active (no soft-expiry)
        let expired_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM one_time_prekeys WHERE device_id = $1::uuid AND is_expired = true",
        )
        .bind(&device_id)
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(
            expired_count, 0,
            "replace_existing=false must not expire old keys"
        );

        let total: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM one_time_prekeys WHERE device_id = $1::uuid")
                .bind(&device_id)
                .fetch_one(&db)
                .await
                .unwrap();
        assert_eq!(total, 8);

        cleanup_device(&db, &device_id).await;
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn test_cleanup_expired_otpks_only_removes_old_expired_keys() {
        let db = get_test_db().await;
        let device_id = insert_test_device(&db).await;

        // Upload and immediately soft-expire keys 1-5 with backdated expired_at
        let keys = make_prekeys(5);
        upload_prekeys(&db, &device_id, &keys, false, &[])
            .await
            .unwrap();

        // Backdate expired_at to 3 days ago to simulate old expired keys
        sqlx::query(
            "UPDATE one_time_prekeys
             SET is_expired = true, expired_at = NOW() - INTERVAL '3 days'
             WHERE device_id = $1::uuid AND key_id <= 3",
        )
        .bind(&device_id)
        .execute(&db)
        .await
        .unwrap();

        // Soft-expire keys 4-5 but keep them recent (< 48h ago)
        sqlx::query(
            "UPDATE one_time_prekeys
             SET is_expired = true, expired_at = NOW() - INTERVAL '1 hour'
             WHERE device_id = $1::uuid AND key_id > 3",
        )
        .bind(&device_id)
        .execute(&db)
        .await
        .unwrap();

        // cleanup_expired_otpks must only delete keys older than 48h
        let deleted = cleanup_expired_otpks(&db).await.unwrap();
        assert!(
            deleted >= 3,
            "should have deleted at least 3 old expired keys"
        );

        // Keys 4-5 (recent soft-expire) must still be present
        let recent_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM one_time_prekeys WHERE device_id = $1::uuid AND key_id > 3",
        )
        .bind(&device_id)
        .fetch_one(&db)
        .await
        .unwrap();
        assert_eq!(
            recent_count, 2,
            "recently expired keys must not be cleaned up yet"
        );

        cleanup_device(&db, &device_id).await;
    }

    // ── PQXDH v2 Kyber keys through the database ────────────────────────────

    /// A device row with everything the bundle query reads. `insert_test_device` above predates
    /// the NOT NULL key columns and fails on today's schema.
    async fn insert_signing_device(
        db: &PgPool,
        device: &SigningDevice,
        with_hybrid_identity: bool,
    ) -> (String, uuid::Uuid) {
        let user_id = uuid::Uuid::new_v4();
        let device_id = uuid::Uuid::new_v4().simple().to_string();
        sqlx::query(
            r#"
            INSERT INTO devices (device_id, user_id, server_hostname, verifying_key,
                                 identity_public, signed_prekey_public, hybrid_identity_key)
            VALUES ($1, $2, 'test', $3, $4, $5, $6)
            "#,
        )
        .bind(&device_id)
        .bind(user_id)
        .bind(device.verifying_key())
        .bind(uuid::Uuid::new_v4().as_bytes().to_vec())
        .bind(vec![1u8; 32])
        .bind(with_hybrid_identity.then(|| device.hybrid_pk.clone()))
        .execute(db)
        .await
        .expect("Failed to insert test device");
        (device_id, user_id)
    }

    /// Upload → bundle, for the fields PQXDH v2 added: what the device signed comes back exactly,
    /// and it verifies the way an initiator will verify it.
    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn test_pqxdh_v2_kyber_keys_round_trip_through_the_bundle() {
        let db = get_test_db().await;
        let device = SigningDevice::new();
        let (device_id, user_id) = insert_signing_device(&db, &device, true).await;
        let now = now_secs();

        let spk = device.kyber_key(1, now - 60);
        upload_kyber_signed_prekey(
            &db,
            &device_id,
            spk.key_id,
            &spk.public_key,
            &spk.signature,
            spk.created_at,
            Some(&spk.hybrid_signature),
        )
        .await
        .unwrap();

        let otpk = device.kyber_key(7, now - 30);
        upload_prekeys(&db, &device_id, &[], false, std::slice::from_ref(&otpk))
            .await
            .unwrap();

        // A key without a signed time is a pre-v2 upload, and nothing is stored for it.
        let mut unsigned_time = device.kyber_key(8, now);
        unsigned_time.created_at = 0;
        assert!(
            upload_prekeys(&db, &device_id, &[], false, &[unsigned_time])
                .await
                .is_err()
        );

        let bundle = get_prekey_bundle(&db, &user_id.to_string(), Some(&device_id), None, true)
            .await
            .unwrap()
            .expect("bundle");

        assert_eq!(
            bundle.kyber_pre_key.as_deref(),
            Some(spk.public_key.as_slice())
        );
        assert_eq!(bundle.kyber_pre_key_created_at, Some(spk.created_at));
        assert_eq!(
            bundle.kyber_pre_key_hybrid_signature.as_deref(),
            Some(spk.hybrid_signature.as_slice())
        );
        assert_eq!(bundle.kyber_one_time_pre_key_id, Some(otpk.key_id));
        assert_eq!(
            bundle.kyber_one_time_pre_key_created_at,
            Some(otpk.created_at)
        );

        let served_otpk = bundle.kyber_one_time_pre_key.unwrap();
        let created_at = bundle.kyber_one_time_pre_key_created_at.unwrap();
        construct_crypto::pqc::verify_kyber_prekey_signature_v2(
            &bundle.verifying_key,
            created_at,
            &served_otpk,
            &bundle.kyber_one_time_pre_key_signature.unwrap(),
        )
        .unwrap();
        construct_crypto::pqc::verify_hybrid_kyber_prekey_signature_v2(
            bundle.hybrid_identity_key.as_deref().unwrap(),
            created_at,
            &served_otpk,
            &bundle.kyber_one_time_pre_key_hybrid_signature.unwrap(),
        )
        .unwrap();

        // Consumed: the next bundle has no one-time key left to give.
        let next = get_prekey_bundle(&db, &user_id.to_string(), Some(&device_id), None, true)
            .await
            .unwrap()
            .unwrap();
        assert!(next.kyber_one_time_pre_key.is_none());
        assert!(next.kyber_one_time_pre_key_signature.is_none());
    }

    /// A Kyber one-time key needs the hybrid identity it is signed with, on the row.
    #[tokio::test]
    #[ignore = "requires PostgreSQL"]
    async fn test_kyber_one_time_keys_need_a_hybrid_identity() {
        let db = get_test_db().await;
        let device = SigningDevice::new();
        let (device_id, _) = insert_signing_device(&db, &device, false).await;
        let otpk = device.kyber_key(7, now_secs());
        assert!(
            upload_prekeys(&db, &device_id, &[], false, &[otpk])
                .await
                .is_err()
        );
    }
}
