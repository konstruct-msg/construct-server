#[path = "../../shared/test_support/postgres.rs"]
mod postgres;
use crate::{core, stickers};
use postgres::Database;
use std::path::{Path, PathBuf};
use uuid::Uuid;
static MIGRATIONS: sqlx::migrate::Migrator = sqlx::migrate!("../shared/migrations");
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!("media-audit-{}", Uuid::new_v4()));
        std::fs::create_dir(&p).unwrap();
        Self(p)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
async fn media(pool: &sqlx::PgPool, dir: &Path, expired: bool) -> String {
    let id = Uuid::new_v4().to_string();
    core::save_metadata(pool, &id, 3, "local", &id, &"a".repeat(64), 3600)
        .await
        .unwrap();
    if expired {
        sqlx::query("UPDATE media_files SET created_at=NOW()-INTERVAL '2 hours',expires_at=NOW()-INTERVAL '1 hour' WHERE media_id=$1").bind(Uuid::parse_str(&id).unwrap()).execute(pool).await.unwrap();
    }
    tokio::fs::write(dir.join(&id), b"e2e").await.unwrap();
    id
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn cleanup_removes_only_expired_media_and_preserves_sticker_packs() {
    let db = Database::new(&MIGRATIONS).await;
    let dir = Directory::new();
    let old = media(&db.pool, &dir.0, true).await;
    let live = media(&db.pool, &dir.0, false).await;
    tokio::fs::write(dir.0.join(format!("{old}.partial")), b"partial")
        .await
        .unwrap();
    let missing = media(&db.pool, &dir.0, true).await;
    tokio::fs::remove_file(dir.0.join(&missing)).await.unwrap();
    // The sticker store is a separate, non-expiring production table.
    let hash = stickers::sha256(b"public sticker");
    sqlx::query("INSERT INTO sticker_blobs(sha256,bytes,width,height) VALUES($1,$2,512,512)")
        .bind(hash.as_slice())
        .bind(b"public sticker".as_slice())
        .execute(&db.pool)
        .await
        .unwrap();
    let pack = Uuid::new_v4().as_bytes().repeat(2);
    sqlx::query("INSERT INTO sticker_packs(pack_id,manifest_bytes,title,publisher,sticker_count,total_bytes,cover_sha256) VALUES($1,$2,'pack','publisher',1,14,$3)").bind(&pack).bind(b"manifest".as_slice()).bind(hash.as_slice()).execute(&db.pool).await.unwrap();
    assert_eq!(
        core::cleanup_expired_media(&db.pool, &dir.0).await.unwrap(),
        2
    );
    assert!(core::get_metadata(&db.pool, &old).await.unwrap().is_none());
    assert!(!dir.0.join(&old).exists());
    assert!(!dir.0.join(format!("{old}.partial")).exists());
    assert!(core::get_metadata(&db.pool, &live).await.unwrap().is_some());
    assert_eq!(tokio::fs::read(dir.0.join(&live)).await.unwrap(), b"e2e");
    let bytes: Vec<u8> = sqlx::query_scalar("SELECT bytes FROM sticker_blobs WHERE sha256=$1")
        .bind(hash.as_slice())
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(bytes, b"public sticker");
    let manifest: Vec<u8> =
        sqlx::query_scalar("SELECT manifest_bytes FROM sticker_packs WHERE pack_id=$1")
            .bind(&pack)
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!(manifest, b"manifest");
    assert_eq!(
        core::cleanup_expired_media(&db.pool, &dir.0).await.unwrap(),
        0
    );
    db.cleanup().await;
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn cleanup_keeps_failed_file_metadata_for_retry_and_continues_healthy_rows() {
    let db = Database::new(&MIGRATIONS).await;
    let dir = Directory::new();
    let bad = media(&db.pool, &dir.0, true).await;
    let good = media(&db.pool, &dir.0, true).await;
    tokio::fs::remove_file(dir.0.join(&bad)).await.unwrap();
    tokio::fs::create_dir(dir.0.join(&bad)).await.unwrap();
    let result = core::cleanup_expired_media(&db.pool, &dir.0).await;
    assert!(
        result.is_err(),
        "filesystem failure must reach the cleanup worker"
    );
    assert!(
        core::get_metadata(&db.pool, &bad).await.unwrap().is_some(),
        "failed deletion must remain retryable"
    );
    assert!(core::get_metadata(&db.pool, &good).await.unwrap().is_none());
    assert!(!dir.0.join(&good).exists());
    tokio::fs::remove_dir(dir.0.join(&bad)).await.unwrap();
    assert_eq!(
        core::cleanup_expired_media(&db.pool, &dir.0).await.unwrap(),
        1
    );
    db.cleanup().await;
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn cleanup_rejects_unsafe_keys_and_does_not_remove_the_retry_record() {
    let db = Database::new(&MIGRATIONS).await;
    let dir = Directory::new();
    let id = media(&db.pool, &dir.0, true).await;
    sqlx::query("UPDATE media_files SET storage_key='../outside' WHERE media_id=$1")
        .bind(Uuid::parse_str(&id).unwrap())
        .execute(&db.pool)
        .await
        .unwrap();
    assert!(core::cleanup_expired_media(&db.pool, &dir.0).await.is_err());
    assert!(core::get_metadata(&db.pool, &id).await.unwrap().is_some());
    assert!(dir.0.join(&id).exists());
    db.cleanup().await;
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn cleanup_reports_partial_failure_and_expires_only_old_orphan_partials() {
    let db = Database::new(&MIGRATIONS).await;
    let dir = Directory::new();
    let id = media(&db.pool, &dir.0, true).await;
    let partial = dir.0.join(format!("{id}.partial"));
    tokio::fs::create_dir(&partial).await.unwrap();
    assert!(core::cleanup_expired_media(&db.pool, &dir.0).await.is_err());
    assert!(core::get_metadata(&db.pool, &id).await.unwrap().is_some());
    tokio::fs::remove_dir(&partial).await.unwrap();
    let old = dir.0.join("orphan.partial");
    let live = dir.0.join("fresh.partial");
    let regular = dir.0.join("regular");
    for p in [&old, &live, &regular] {
        std::fs::write(p, b"bytes").unwrap();
    }
    std::fs::File::open(&live)
        .unwrap()
        .set_times(
            std::fs::FileTimes::new()
                .set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(60)),
        )
        .unwrap();
    for p in [&old, &regular] {
        std::fs::File::open(p)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(std::time::SystemTime::UNIX_EPOCH))
            .unwrap();
    }
    assert_eq!(
        core::cleanup_expired_media(&db.pool, &dir.0).await.unwrap(),
        1
    );
    assert!(!old.exists());
    assert!(live.exists());
    assert!(regular.exists());
    let blocked = dir.0.join("blocked.partial");
    std::fs::create_dir(&blocked).unwrap();
    std::fs::File::open(&blocked)
        .unwrap()
        .set_times(std::fs::FileTimes::new().set_modified(std::time::SystemTime::UNIX_EPOCH))
        .unwrap();
    assert!(core::cleanup_expired_media(&db.pool, &dir.0).await.is_err());
    assert!(blocked.exists());
    db.cleanup().await;
}
