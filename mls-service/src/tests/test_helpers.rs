#![allow(dead_code)]

use chrono::Utc;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use uuid::Uuid;

use crate::helpers::sha256_bytes;

/// Create a test database connection pool
pub(crate) async fn get_test_db() -> Arc<sqlx::PgPool> {
    let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    Arc::new(
        sqlx::PgPool::connect(&db_url)
            .await
            .expect("Failed to connect"),
    )
}

/// Create a test user and device with Ed25519 keypair
/// Returns (user_id, device_id, signing_key)
pub(crate) async fn create_test_device(db: &sqlx::PgPool) -> (Uuid, String, SigningKey) {
    let user_id = Uuid::new_v4();
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    // Insert user
    sqlx::query(
        "INSERT INTO users (id, primary_device_id) VALUES ($1, NULL) ON CONFLICT (id) DO NOTHING",
    )
    .bind(user_id)
    .execute(db)
    .await
    .expect("Failed to insert test user");

    // Generate device_id: SHA256 of verifying_key, first 16 bytes
    let mut hasher = Sha256::new();
    hasher.update(verifying_key.as_bytes());
    let hash = hasher.finalize();
    let device_id = hex::encode(&hash[..16]);

    // Insert device
    sqlx::query(
        r#"
            INSERT INTO devices (device_id, user_id, server_hostname, verifying_key,
                                 identity_public, signed_prekey_public, registered_at)
            VALUES ($1, $2, 'test.local', $3, $4, $5, $6)
            ON CONFLICT (device_id) DO UPDATE SET user_id = EXCLUDED.user_id
            "#,
    )
    .bind(&device_id)
    .bind(user_id)
    .bind(verifying_key.as_bytes().to_vec())
    .bind(vec![0u8; 32])
    .bind(vec![0u8; 32])
    .bind(Utc::now())
    .execute(db)
    .await
    .expect("Failed to insert test device");

    sqlx::query(
        "UPDATE users SET primary_device_id = COALESCE(primary_device_id, $2) WHERE id = $1",
    )
    .bind(user_id)
    .bind(&device_id)
    .execute(db)
    .await
    .expect("Failed to set primary device");

    (user_id, device_id, signing_key)
}

/// Create a test group directly in DB
/// Returns group_id
pub(crate) async fn create_test_group_in_db(db: &sqlx::PgPool, device_id: &str) -> Uuid {
    let group_id = Uuid::new_v4();
    let now = Utc::now();

    sqlx::query(
        r#"
            INSERT INTO mls_groups
                (group_id, epoch, ratchet_tree, encrypted_group_context,
                 max_members, message_retention_days, threads_enabled, created_at)
            VALUES ($1, 0, $2, $3, 2048, 90, false, $4)
            "#,
    )
    .bind(group_id)
    .bind(vec![0u8; 32])
    .bind(vec![0u8; 32])
    .bind(now)
    .execute(db)
    .await
    .expect("Failed to insert test group");

    sqlx::query(
        "INSERT INTO group_members (group_id, device_id, leaf_index, joined_at) VALUES ($1, $2, 0, $3)",
    )
    .bind(group_id)
    .bind(device_id)
    .bind(now)
    .execute(db)
    .await
    .expect("Failed to add creator to group");

    sqlx::query(
        "INSERT INTO group_admins (group_id, device_id, role, is_creator, granted_at) VALUES ($1, $2, 1, true, $3)",
    )
    .bind(group_id)
    .bind(device_id)
    .bind(now)
    .execute(db)
    .await
    .expect("Failed to add creator as admin");

    group_id
}

/// Create metadata with x-user-id and x-device-id headers
pub(crate) fn create_metadata(user_id: &Uuid, device_id: &str) -> tonic::metadata::MetadataMap {
    let mut meta = tonic::metadata::MetadataMap::new();
    meta.insert("x-user-id", user_id.to_string().parse().unwrap());
    meta.insert("x-device-id", device_id.parse().unwrap());
    meta
}

/// Helper: publish a KeyPackage for a device and return key_package_ref
pub(crate) async fn publish_test_key_package(
    db: &sqlx::PgPool,
    user_id: Uuid,
    device_id: &str,
) -> Vec<u8> {
    let kp = format!("test-kp:{user_id}:{device_id}:{}", Uuid::new_v4()).into_bytes();
    let kp_ref = sha256_bytes(&kp);
    let now = Utc::now();

    sqlx::query(
        r#"
            INSERT INTO group_key_packages
                (user_id, device_id, key_package, key_package_ref, published_at, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
    )
    .bind(user_id)
    .bind(device_id)
    .bind(&kp)
    .bind(&kp_ref)
    .bind(now)
    .bind(now + chrono::Duration::days(30))
    .execute(db)
    .await
    .expect("Failed to publish test KeyPackage");

    kp_ref
}
