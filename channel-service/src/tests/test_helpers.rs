#![allow(dead_code)]

use chrono::Utc;
use std::sync::Arc;
use uuid::Uuid;

pub(crate) async fn get_test_db() -> Arc<sqlx::PgPool> {
    let mut db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    // Local PostgreSQL typically doesn't use TLS — disable to avoid SSL errors
    if (db_url.contains("localhost") || db_url.contains("127.0.0.1"))
        && !db_url.contains("sslmode=")
    {
        db_url.push_str(if db_url.contains('?') {
            "&sslmode=disable"
        } else {
            "?sslmode=disable"
        });
    }
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
    let device_id_bytes = Uuid::new_v4().as_bytes()[..16].to_vec();
    let device_id = hex::encode(&device_id_bytes);

    // Generate unique identity_public per device to avoid UNIQUE constraint violation
    let identity_public = Uuid::new_v4().as_bytes().to_vec();

    sqlx::query("INSERT INTO users (id) VALUES ($1) ON CONFLICT (id) DO NOTHING")
        .bind(user_id)
        .execute(db)
        .await
        .expect("Failed to insert test user");

    sqlx::query(
        r#"
        INSERT INTO devices (device_id, user_id, server_hostname, verifying_key,
                             identity_public, signed_prekey_public, registered_at, is_active)
        VALUES ($1, $2, 'test.local', $3, $4, $5, $6, TRUE)
        ON CONFLICT (device_id) DO NOTHING
        "#,
    )
    .bind(&device_id)
    .bind(user_id)
    .bind(identity_public.clone()) // verifying_key
    .bind(identity_public) // unique identity_public per call
    .bind(vec![0u8; 32]) // signed_prekey_public (placeholder)
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
