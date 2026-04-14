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

/// ML-KEM-1024 public key size in bytes (NIST FIPS 203)
pub const KYBER_PUBLIC_KEY_SIZE: usize = 1184;
/// ML-KEM-1024 ciphertext size in bytes (carried in PreKeySignalMessage.kem_ciphertext)
#[allow(dead_code)]
pub const KYBER_CIPHERTEXT_SIZE: usize = 1568;
/// Ed25519 signature size in bytes
pub const ED25519_SIGNATURE_SIZE: usize = 64;

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

/// ML-KEM-1024 one-time pre-key with signature
#[derive(Debug, Clone)]
pub struct KyberOneTimePreKey {
    pub key_id: u32,
    /// Exactly `KYBER_PUBLIC_KEY_SIZE` (1184) bytes
    pub public_key: Vec<u8>,
    /// Ed25519 signature, exactly `ED25519_SIGNATURE_SIZE` (64) bytes
    pub signature: Vec<u8>,
}

/// Validate ML-KEM-1024 public key size.
/// Returns `Err` if the key is not exactly 1184 bytes.
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

/// Cryptographically verify a prekey signature.
///
/// Message = `"KonstruktX3DH-v1" || [0x00, suite_id] || public_key`
///
/// `suite_id`: 0x01 = ClassicX25519, 0x10 = HybridKyber1024X25519
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

/// Get pre-key bundle for a device (consumes one-time pre-key if available)
pub async fn get_prekey_bundle(
    db: &PgPool,
    user_id: &str,
    device_id: Option<&str>,
    bundle_signing_key: Option<&SigningKey>,
) -> Result<Option<PreKeyBundle>> {
    // First, get device info (including Kyber SPK columns added in migration 028)
    let device = if let Some(did) = device_id {
        sqlx::query_as::<_, DeviceRow>(
            r#"
            SELECT device_id, identity_public, verifying_key, signed_prekey_public,
                   signed_prekey_id, signed_prekey_signature, crypto_suites->>0 AS crypto_suite, registered_at,
                   kyber_signed_pre_key, kyber_signed_pre_key_id, kyber_signed_pre_key_signature,
                   spk_uploaded_at, spk_rotation_epoch, kyber_spk_uploaded_at, kyber_spk_rotation_epoch
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
                   spk_uploaded_at, spk_rotation_epoch, kyber_spk_uploaded_at, kyber_spk_rotation_epoch
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
    let otp = sqlx::query_as::<_, OneTimePreKeyRow>(
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
    .await?;

    // Try to consume a Kyber one-time pre-key (soft-delete, same pattern as classic OTPK)
    let kyber_otp = sqlx::query_as::<_, KyberOneTimePreKeyRow>(
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
        RETURNING key_id, public_key, signature
        "#,
    )
    .bind(&device.device_id)
    .fetch_optional(db)
    .await?;

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
        spk_uploaded_at: device.spk_uploaded_at,
        spk_rotation_epoch: device.spk_rotation_epoch as u32,
        kyber_spk_uploaded_at: device.kyber_spk_uploaded_at,
        kyber_spk_rotation_epoch: device.kyber_spk_rotation_epoch as u32,
        bundle_signature: None,
        kt_proof: None,
    };
    bundle.bundle_signature = bundle_signing_key.map(|sk| sign_bundle(&bundle, sk));
    if let Some(sk) = bundle_signing_key {
        match crate::kt::build_kt_proof(db, &bundle.device_id, &bundle.identity_key, sk).await {
            Ok(proof) => bundle.kt_proof = Some(proof),
            Err(e) => {
                tracing::warn!(error = %e, device_id = %bundle.device_id, "KT proof generation failed")
            }
        }
    }
    Ok(Some(bundle))
}

/// Get pre-key bundles for all devices of a user
pub async fn get_prekey_bundles(
    db: &PgPool,
    user_id: &str,
    device_ids: Option<&[String]>,
    bundle_signing_key: Option<&SigningKey>,
) -> Result<(Vec<PreKeyBundle>, Vec<String>)> {
    let devices: Vec<DeviceRow> = if let Some(ids) = device_ids {
        sqlx::query_as(
            r#"
            SELECT device_id, identity_public, verifying_key, signed_prekey_public,
                   signed_prekey_id, signed_prekey_signature, crypto_suites->>0 AS crypto_suite, registered_at,
                   kyber_signed_pre_key, kyber_signed_pre_key_id, kyber_signed_pre_key_signature,
                   spk_uploaded_at, spk_rotation_epoch, kyber_spk_uploaded_at, kyber_spk_rotation_epoch
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
                   spk_uploaded_at, spk_rotation_epoch, kyber_spk_uploaded_at, kyber_spk_rotation_epoch
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
        let otp = sqlx::query_as::<_, OneTimePreKeyRow>(
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
        .await?;

        // Try to consume a Kyber OTPK for this device
        let kyber_otp = sqlx::query_as::<_, KyberOneTimePreKeyRow>(
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
            RETURNING key_id, public_key, signature
            "#,
        )
        .bind(&device.device_id)
        .fetch_optional(db)
        .await?;

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
            spk_uploaded_at: device.spk_uploaded_at,
            spk_rotation_epoch: device.spk_rotation_epoch as u32,
            kyber_spk_uploaded_at: device.kyber_spk_uploaded_at,
            kyber_spk_rotation_epoch: device.kyber_spk_rotation_epoch as u32,
            bundle_signature: None,
            kt_proof: None,
        };
        bundle.bundle_signature = bundle_signing_key.map(|sk| sign_bundle(&bundle, sk));
        if let Some(sk) = bundle_signing_key {
            match crate::kt::build_kt_proof(db, &bundle.device_id, &bundle.identity_key, sk).await {
                Ok(proof) => bundle.kt_proof = Some(proof),
                Err(e) => {
                    tracing::warn!(error = %e, device_id = %bundle.device_id, "KT proof generation failed")
                }
            }
        }
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

    Ok((bundles, unavailable))
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

    // Validate Kyber key sizes and verify signatures before any DB writes
    if !kyber_pre_keys.is_empty() {
        let verifying_key: Vec<u8> = sqlx::query_scalar(
            "SELECT verifying_key FROM devices WHERE device_id = $1 AND is_active = true",
        )
        .bind(device_id)
        .fetch_one(db)
        .await
        .map_err(|_| anyhow::anyhow!("Failed to fetch device verifying key"))?;

        for k in kyber_pre_keys {
            validate_kyber_public_key(&k.public_key)?;
            validate_ed25519_signature(&k.signature)?;
            // Suite 0x10 = HybridKyber1024X25519
            verify_prekey_signature(&verifying_key, 0x10, &k.public_key, &k.signature)?;
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
            INSERT INTO kyber_one_time_pre_keys (device_id, key_id, public_key, signature)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (device_id, key_id) DO NOTHING
            "#,
        )
        .bind(device_id)
        .bind(kk.key_id as i32)
        .bind(&kk.public_key)
        .bind(&kk.signature)
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

    Ok((classic_count as u32, kyber_count as u32))
}

/// Get count of remaining one-time pre-keys
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
/// Validates key size (1184 bytes) and signature size (64 bytes) before writing.
pub async fn upload_kyber_signed_prekey(
    db: &PgPool,
    device_id: &str,
    key_id: u32,
    public_key: &[u8],
    signature: &[u8],
) -> Result<u32> {
    validate_kyber_public_key(public_key)?;
    validate_ed25519_signature(signature)?;

    let verifying_key: Vec<u8> = sqlx::query_scalar(
        "SELECT verifying_key FROM devices WHERE device_id = $1 AND is_active = true",
    )
    .bind(device_id)
    .fetch_one(db)
    .await
    .map_err(|_| anyhow::anyhow!("Failed to fetch device verifying key"))?;

    // Suite 0x10 = HybridKyber1024X25519
    verify_prekey_signature(&verifying_key, 0x10, public_key, signature)?;

    let new_epoch: i32 = sqlx::query_scalar(
        r#"
        UPDATE devices
        SET kyber_signed_pre_key           = $2,
            kyber_signed_pre_key_id        = $3,
            kyber_signed_pre_key_signature = $4,
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
    .fetch_one(db)
    .await?;

    Ok(new_epoch as u32)
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
) -> Result<(DateTime<Utc>, u32)> {
    // Verify Classic SPK signature before archiving or updating.
    // Kyber SPK is verified in upload_kyber_signed_prekey via verify_prekey_signature(0x10).
    // suite_id 0x01 = ClassicX25519 (see verify_prekey_signature header comment).
    let verifying_key_bytes: Vec<u8> = sqlx::query_scalar(
        "SELECT verifying_key FROM devices WHERE device_id = $1 AND is_active = true",
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
    if let Some(old) = current {
        if let Some(sig) = old.signed_prekey_signature {
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
    }

    // Update device with new signed prekey, upload timestamp, and incremented epoch
    let new_epoch: i32 = sqlx::query_scalar(
        r#"
        UPDATE devices
        SET signed_prekey_public = $2,
            signed_prekey_id = $3,
            signed_prekey_signature = $4,
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
    // SPK timestamp and epoch columns (nullable, added in migration 031)
    spk_uploaded_at: Option<DateTime<Utc>>,
    spk_rotation_epoch: i32,
    kyber_spk_uploaded_at: Option<DateTime<Utc>>,
    kyber_spk_rotation_epoch: i32,
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
    #[allow(dead_code)]
    signature: Vec<u8>,
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
        let key = vec![0xAB_u8; KYBER_PUBLIC_KEY_SIZE]; // exactly 1184 bytes
        assert!(validate_kyber_public_key(&key).is_ok());
    }

    #[test]
    fn test_validate_kyber_public_key_wrong_size_rejected() {
        let short = vec![0u8; 32]; // X25519 size — must be rejected
        let err = validate_kyber_public_key(&short).unwrap_err();
        assert!(
            err.to_string().contains("1184"),
            "error must mention expected size"
        );

        let long = vec![0u8; 1568]; // ciphertext size — not a valid pubkey
        assert!(validate_kyber_public_key(&long).is_err());

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
        // Sanity: ML-KEM-1024 spec mandates 1184 bytes
        assert_eq!(KYBER_PUBLIC_KEY_SIZE, 1184);
        assert_eq!(KYBER_CIPHERTEXT_SIZE, 1568);
        assert_eq!(ED25519_SIGNATURE_SIZE, 64);
    }

    #[test]
    fn test_kyber_otpk_construction() {
        let key = KyberOneTimePreKey {
            key_id: 42,
            public_key: vec![0u8; KYBER_PUBLIC_KEY_SIZE],
            signature: vec![0u8; ED25519_SIGNATURE_SIZE],
        };
        assert_eq!(key.key_id, 42);
        assert_eq!(key.public_key.len(), KYBER_PUBLIC_KEY_SIZE);
        assert_eq!(key.signature.len(), ED25519_SIGNATURE_SIZE);
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
}
