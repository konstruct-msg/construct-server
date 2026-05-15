#![allow(dead_code)]

use chrono::Utc;
use std::sync::Arc;
use uuid::Uuid;

pub(crate) async fn get_test_db() -> Arc<sqlx::PgPool> {
    let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = sqlx::PgPool::connect(&db_url)
        .await
        .expect("Failed to connect");
    sqlx::migrate!("../shared/migrations")
        .run(&pool)
        .await
        .expect("Failed to run migrations");
    Arc::new(pool)
}

pub(crate) async fn create_test_device(db: &sqlx::PgPool) -> (Uuid, String) {
    let user_id = Uuid::new_v4();
    let device_id = hex::encode(&Uuid::new_v4().as_bytes()[..16]);

    sqlx::query("INSERT INTO users (id) VALUES ($1) ON CONFLICT (id) DO NOTHING")
        .bind(user_id)
        .execute(db)
        .await
        .expect("Failed to insert test user");

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
    .bind(vec![0u8; 32])
    .bind(vec![1u8; 32])
    .bind(vec![2u8; 32])
    .bind(Utc::now())
    .execute(db)
    .await
    .expect("Failed to insert test device");

    sqlx::query("UPDATE users SET primary_device_id = $2 WHERE id = $1")
        .bind(user_id)
        .bind(&device_id)
        .execute(db)
        .await
        .expect("Failed to set primary device");

    (user_id, device_id)
}

pub(crate) fn create_metadata(user_id: &Uuid, device_id: &str) -> tonic::metadata::MetadataMap {
    let mut meta = tonic::metadata::MetadataMap::new();
    meta.insert("x-user-id", user_id.to_string().parse().unwrap());
    meta.insert("x-device-id", device_id.parse().unwrap());
    meta
}
