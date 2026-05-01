//! Background cleanup job for expired MLS data.
//! Runs every 24 hours (configurable) and calls PostgreSQL cleanup functions.

use sqlx::PgPool;
use tracing::{error, info};

/// Cleanup statistics returned by PostgreSQL function
pub struct CleanupStats {
    pub operation: String,
    pub deleted_count: i32,
}

/// Run the master cleanup function
pub async fn run_cleanup(db: &PgPool) -> Result<Vec<CleanupStats>, sqlx::Error> {
    let rows: Vec<(String, i32)> =
        sqlx::query_as("SELECT operation, deleted_count FROM cleanup_mls_expired()")
            .fetch_all(db)
            .await?;

    let stats: Vec<CleanupStats> = rows
        .into_iter()
        .map(|(op, count)| CleanupStats {
            operation: op,
            deleted_count: count,
        })
        .collect();

    Ok(stats)
}

/// Background cleanup task that runs periodically
pub async fn cleanup_worker(
    db: PgPool,
    interval_hours: u64,
    shutdown_signal: impl std::future::Future<Output = ()> + Send + 'static,
) {
    info!(
        interval_hours = interval_hours,
        "Starting MLS cleanup worker"
    );

    let mut interval =
        tokio::time::interval(tokio::time::Duration::from_secs(interval_hours * 3600));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    tokio::pin!(shutdown_signal);

    loop {
        tokio::select! {
            _ = &mut shutdown_signal => {
                info!("MLS cleanup worker shutting down");
                break;
            }
            _ = interval.tick() => {
                info!("Running scheduled MLS cleanup");

                match run_cleanup(&db).await {
                    Ok(stats) => {
                        let mut total = 0;
                        for stat in &stats {
                            if stat.deleted_count > 0 {
                                info!(
                                    operation = %stat.operation,
                                    deleted = stat.deleted_count,
                                    "Cleanup completed"
                                );
                            }
                            total += stat.deleted_count;
                        }
                        info!(total_deleted = total, "MLS cleanup cycle complete");
                    }
                    Err(e) => {
                        error!(error = %e, "MLS cleanup failed");
                    }
                }
            }
        }
    }
}

/// Start cleanup worker in background
pub fn start_cleanup_worker(db: PgPool, interval_hours: u64) -> tokio::task::JoinHandle<()> {
    let shutdown = construct_server_shared::shutdown_signal();
    tokio::spawn(async move {
        cleanup_worker(db, interval_hours, shutdown).await;
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // Requires database with cleanup function
    async fn test_run_cleanup() {
        let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
        let db = PgPool::connect(&db_url).await.unwrap();

        let stats = run_cleanup(&db).await.unwrap();

        assert!(!stats.is_empty());
        assert!(stats.iter().any(|s| s.operation == "group_messages"));
        assert!(stats.iter().any(|s| s.operation == "dissolved_groups"));
    }
}
