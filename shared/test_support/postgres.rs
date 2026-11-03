//! Test-only PostgreSQL isolation, shared by DB contracts and their RPC consumers.
//! A unique schema gets the real migrations; even a panicking mutation drops only that schema.
use sqlx::{PgPool, migrate::Migrator, postgres::PgConnectOptions, postgres::PgPoolOptions};
use uuid::Uuid;

pub(crate) struct Database {
    pub(crate) pool: PgPool,
    url: String,
    schema: String,
}

impl Database {
    pub(crate) async fn new(migrations: &Migrator) -> Self {
        let url = std::env::var("DATABASE_URL").expect("DATABASE_URL required for Postgres tests");
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .expect("Postgres required");
        let schema = format!("contract_{}", Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin)
            .await
            .unwrap();
        admin.close().await;
        let options: PgConnectOptions = url.parse().unwrap();
        let pool = PgPoolOptions::new()
            .max_connections(16)
            .connect_with(options.application_name(&schema).options([
                ("search_path", schema.as_str()),
                ("statement_timeout", "10000"),
            ]))
            .await
            .unwrap();
        let db = Self { pool, url, schema };
        migrations
            .run(&db.pool)
            .await
            .expect("all migrations must apply to an empty schema");
        db
    }

    pub(crate) async fn cleanup(mut self) {
        self.pool.close().await;
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&self.url)
            .await
            .unwrap();
        sqlx::query(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .execute(&admin)
            .await
            .unwrap();
        self.schema.clear();
        admin.close().await;
    }
}

impl Drop for Database {
    fn drop(&mut self) {
        if self.schema.is_empty() {
            return;
        }
        let schema = std::mem::take(&mut self.schema);
        let url = self.url.clone();
        let result = std::thread::spawn(move || -> anyhow::Result<()> {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(async {
                    let options: PgConnectOptions = url.parse()?;
                    let admin = PgPoolOptions::new()
                        .max_connections(1)
                        .connect_with(options.options([("lock_timeout", "3000")]))
                        .await?;
                    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
                        .execute(&admin)
                        .await?;
                    admin.close().await;
                    Ok(())
                })
        })
        .join();
        if !matches!(result, Ok(Ok(()))) {
            eprintln!("Postgres fixture cleanup failed: {result:?}");
        }
    }
}
