// Key Transparency — server-side Merkle tree operations
//
// Implements RFC 6962 §2 Merkle Tree Hash for the kt_leaves log.
// Algorithm matches construct-core's key_transparency.rs exactly:
//   Leaf hash  : SHA-256(0x00 || device_id_utf8 || identity_key_raw)
//   Node hash  : SHA-256(0x01 || left_hash || right_hash)
//
// The server always holds all leaves and computes proofs on demand.
// This is correct for current scale; a cached incremental tree can be added later.

use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use sqlx::PgPool;

// ────────────────────────────────────────────────────────────────────────────
// Hashing primitives
// ────────────────────────────────────────────────────────────────────────────

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// H(0x00 || device_id_utf8 || identity_key_raw)
pub fn leaf_hash(device_id: &str, identity_key_raw: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(1 + device_id.len() + identity_key_raw.len());
    buf.push(0x00u8);
    buf.extend_from_slice(device_id.as_bytes());
    buf.extend_from_slice(identity_key_raw);
    sha256(&buf)
}

fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 65];
    buf[0] = 0x01;
    buf[1..33].copy_from_slice(left);
    buf[33..65].copy_from_slice(right);
    sha256(&buf)
}

// ────────────────────────────────────────────────────────────────────────────
// RFC 6962 Merkle Tree Hash
// ────────────────────────────────────────────────────────────────────────────

/// Largest power of 2 strictly less than `n` (n >= 2).
fn split(n: usize) -> usize {
    debug_assert!(n >= 2);
    let mut k = 1usize;
    while k < n {
        k <<= 1;
    }
    k >> 1
}

/// Recursively compute the Merkle root of `leaves`.
pub fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    match leaves.len() {
        0 => sha256(b""),
        1 => leaves[0],
        n => {
            let k = split(n);
            let left = merkle_root(&leaves[..k]);
            let right = merkle_root(&leaves[k..]);
            node_hash(&left, &right)
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Inclusion proof
// ────────────────────────────────────────────────────────────────────────────

/// Generate an RFC 6962 inclusion proof for the leaf at `index` in `leaves`.
/// Returns `(proof_hashes, root_hash)`.
/// Proof elements are ordered leaf-to-root (innermost sibling first).
pub fn generate_inclusion_proof(
    leaves: &[[u8; 32]],
    index: usize,
) -> Option<(Vec<[u8; 32]>, [u8; 32])> {
    if leaves.is_empty() || index >= leaves.len() {
        return None;
    }
    let proof = inclusion_proof_inner(leaves, index);
    let root = merkle_root(leaves);
    Some((proof, root))
}

fn inclusion_proof_inner(leaves: &[[u8; 32]], index: usize) -> Vec<[u8; 32]> {
    let n = leaves.len();
    if n == 1 {
        return vec![];
    }
    let k = split(n);
    if index < k {
        let mut proof = inclusion_proof_inner(&leaves[..k], index);
        proof.push(merkle_root(&leaves[k..]));
        proof
    } else {
        let mut proof = inclusion_proof_inner(&leaves[k..], index - k);
        proof.push(merkle_root(&leaves[..k]));
        proof
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Inclusion proof verification (used in integration tests)
// ────────────────────────────────────────────────────────────────────────────

/// Verify an inclusion proof. Returns `true` iff the proof is valid.
#[cfg(test)]
pub fn verify_inclusion(
    leaf: &[u8; 32],
    proof: &[[u8; 32]],
    index: usize,
    tree_size: usize,
    root: &[u8; 32],
) -> bool {
    if tree_size == 0 || index >= tree_size {
        return false;
    }
    inclusion_reconstruct(leaf, proof, index, tree_size) == Some(*root)
}

#[cfg(test)]
fn inclusion_reconstruct(
    leaf: &[u8; 32],
    proof: &[[u8; 32]],
    index: usize,
    size: usize,
) -> Option<[u8; 32]> {
    if proof.is_empty() {
        return if size == 1 && index == 0 {
            Some(*leaf)
        } else {
            None
        };
    }
    let k = split(size);
    let sibling = proof[proof.len() - 1];
    let inner = &proof[..proof.len() - 1];
    if index < k {
        let left = inclusion_reconstruct(leaf, inner, index, k)?;
        Some(node_hash(&left, &sibling))
    } else {
        let right = inclusion_reconstruct(leaf, inner, index - k, size - k)?;
        Some(node_hash(&sibling, &right))
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Signed Tree Head helper
// ────────────────────────────────────────────────────────────────────────────

/// Canonical bytes for Ed25519 STH signature:
/// `"ConstructKT-v1" || tree_size (8 bytes BE) || root_hash (32 bytes)`
pub fn tree_head_signable(tree_size: u64, root: &[u8; 32]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(54);
    buf.extend_from_slice(b"ConstructKT-v1");
    buf.extend_from_slice(&tree_size.to_be_bytes());
    buf.extend_from_slice(root);
    buf
}

// ────────────────────────────────────────────────────────────────────────────
// Database helpers
// ────────────────────────────────────────────────────────────────────────────

/// Append a leaf for `device_id` if the identity key has changed since the last entry.
///
/// Behaviour:
/// - First registration: inserts the leaf, returns its 0-based index.
/// - Same key seen again: idempotent — returns the existing index without inserting.
/// - Key rotation: appends a **new** row so the rotation is permanently recorded in
///   the append-only log, then returns the new 0-based index.
///
/// Requires migration 047 (UNIQUE constraint on device_id dropped).
pub async fn db_ensure_leaf(db: &PgPool, device_id: &str, lhash: [u8; 32]) -> Result<u64> {
    // Find the most recent leaf for this device (if any).
    let latest: Option<(i64, Vec<u8>)> = sqlx::query_as(
        "SELECT id, leaf_hash FROM kt_leaves WHERE device_id = $1 ORDER BY id DESC LIMIT 1",
    )
    .bind(device_id)
    .fetch_optional(db)
    .await
    .context("kt_ensure_leaf: fetch latest failed")?;

    if let Some((existing_id, existing_hash)) = latest {
        if existing_hash.as_slice() == lhash.as_slice() {
            // Same key — idempotent, return existing index.
            return Ok((existing_id - 1) as u64);
        }
        // Hash differs — identity key rotated; append new leaf and log the event.
        tracing::warn!(
            device_id = %device_id,
            "KT: identity key rotation detected — appending new leaf"
        );
    }

    // Insert new leaf (either first registration or key rotation).
    let row: (i64,) =
        sqlx::query_as("INSERT INTO kt_leaves (device_id, leaf_hash) VALUES ($1, $2) RETURNING id")
            .bind(device_id)
            .bind(lhash.as_slice())
            .fetch_one(db)
            .await
            .context("kt_ensure_leaf: insert failed")?;

    Ok((row.0 - 1) as u64)
}

/// Load all leaves ordered by insertion order (id ASC).
/// Returns `Vec<[u8; 32]>`.
pub async fn db_get_all_leaves(db: &PgPool) -> Result<Vec<[u8; 32]>> {
    let rows: Vec<(Vec<u8>,)> = sqlx::query_as("SELECT leaf_hash FROM kt_leaves ORDER BY id ASC")
        .fetch_all(db)
        .await
        .context("kt_get_all_leaves: fetch failed")?;

    rows.into_iter()
        .map(|(h,)| {
            h.try_into()
                .map_err(|_| anyhow::anyhow!("leaf_hash is not 32 bytes"))
        })
        .collect()
}

// ────────────────────────────────────────────────────────────────────────────
// Build KtProof for a device
// ────────────────────────────────────────────────────────────────────────────

/// Build a complete `KtProof` for `device_id`.
///
/// 1. Computes the leaf hash.
/// 2. Ensures the leaf exists in the log (idempotent).
/// 3. Loads all leaves and generates the inclusion proof.
/// 4. Signs the Signed Tree Head with `signing_key`.
pub async fn build_kt_proof(
    db: &PgPool,
    device_id: &str,
    identity_key: &[u8],
    signing_key: &SigningKey,
) -> Result<KtProof> {
    use ed25519_dalek::Signer;

    let lhash = leaf_hash(device_id, identity_key);
    let leaf_index = db_ensure_leaf(db, device_id, lhash).await?;
    let all_leaves = db_get_all_leaves(db).await?;
    let tree_size = all_leaves.len() as u64;

    let (proof_hashes_raw, root_arr) = generate_inclusion_proof(&all_leaves, leaf_index as usize)
        .ok_or_else(|| {
        anyhow::anyhow!("inclusion proof generation failed for index {leaf_index}")
    })?;

    let signable = tree_head_signable(tree_size, &root_arr);
    let signature = signing_key.sign(&signable);

    Ok(KtProof {
        leaf_index,
        tree_size,
        root_hash: root_arr.to_vec(),
        proof_hashes: proof_hashes_raw.into_iter().map(|h| h.to_vec()).collect(),
        tree_head_signature: signature.to_bytes().to_vec(),
    })
}

// ────────────────────────────────────────────────────────────────────────────
// KtProof — the inclusion proof struct returned with bundles
// ────────────────────────────────────────────────────────────────────────────

/// Inclusion proof to attach to a `GetPreKeyBundleResponse`.
#[derive(Debug, Clone)]
pub struct KtProof {
    pub leaf_index: u64,
    pub tree_size: u64,
    pub root_hash: Vec<u8>,           // 32 bytes
    pub proof_hashes: Vec<Vec<u8>>,   // each 32 bytes, leaf-to-root order
    pub tree_head_signature: Vec<u8>, // Ed25519 signature over tree_head_signable()
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(n: usize) -> Vec<[u8; 32]> {
        (0..n)
            .map(|i| {
                let id = format!("dev-{i}");
                let key = [i as u8; 32];
                leaf_hash(&id, &key)
            })
            .collect()
    }

    #[test]
    fn test_inclusion_all_positions() {
        for n in [1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17] {
            let ls = leaves(n);
            let root = merkle_root(&ls);
            for i in 0..n {
                let (proof, proof_root) = generate_inclusion_proof(&ls, i).unwrap();
                assert_eq!(root, proof_root, "n={n} i={i}");
                assert!(verify_inclusion(&ls[i], &proof, i, n, &root), "n={n} i={i}");
            }
        }
    }

    #[test]
    fn test_wrong_leaf_rejected() {
        let ls = leaves(4);
        let root = merkle_root(&ls);
        let (proof, _) = generate_inclusion_proof(&ls, 0).unwrap();
        assert!(!verify_inclusion(&ls[1], &proof, 0, 4, &root));
    }

    #[test]
    fn test_tree_head_signable_length() {
        let root = [0u8; 32];
        let bytes = tree_head_signable(42, &root);
        assert_eq!(bytes.len(), 54); // 14 + 8 + 32
        assert!(bytes.starts_with(b"ConstructKT-v1"));
    }
}
