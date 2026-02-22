// ============================================================================
// Key Management Audit Logging
// ============================================================================
//
// Provides audit logging for key operations to support:
// - SOC 2 compliance
// - GDPR requirements
// - Security incident investigation
// - Anomaly detection
//
// ============================================================================

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::keys::KeyType;
use crate::db::DbPool;

/// Audit event types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    /// Key rotation started
    RotationStarted,
    /// Key rotation completed successfully
    RotationCompleted,
    /// Key rotation failed
    RotationFailed,
    /// Emergency key revocation
    EmergencyRevoke,
    /// Key accessed for signing
    KeySign,
    /// Key accessed for verification
    KeyVerify,
    /// Key accessed for encryption
    KeyEncrypt,
    /// Key accessed for decryption
    KeyDecrypt,
    /// Key loaded from Vault
    KeyLoaded,
    /// Key policy changed
    PolicyChanged,
}

impl std::fmt::Display for AuditEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditEventType::RotationStarted => write!(f, "rotation_started"),
            AuditEventType::RotationCompleted => write!(f, "rotation_completed"),
            AuditEventType::RotationFailed => write!(f, "rotation_failed"),
            AuditEventType::EmergencyRevoke => write!(f, "emergency_revoke"),
            AuditEventType::KeySign => write!(f, "key_sign"),
            AuditEventType::KeyVerify => write!(f, "key_verify"),
            AuditEventType::KeyEncrypt => write!(f, "key_encrypt"),
            AuditEventType::KeyDecrypt => write!(f, "key_decrypt"),
            AuditEventType::KeyLoaded => write!(f, "key_loaded"),
            AuditEventType::PolicyChanged => write!(f, "policy_changed"),
        }
    }
}

/// Log rotation started event
#[allow(dead_code)]
pub async fn log_rotation_started(
    db: &DbPool,
    key_type: KeyType,
    old_key_id: Option<&str>,
    new_key_id: &str,
    initiated_by: &str,
    reason: &str,
) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO key_rotation_audit (
            key_type, old_key_id, new_key_id,
            event_type, initiated_by, reason, success
        ) VALUES ($1, $2, $3, $4, $5, $6, $7)
        "#,
    )
    .bind(key_type.to_string())
    .bind(old_key_id)
    .bind(new_key_id)
    .bind("rotation_started")
    .bind(initiated_by)
    .bind(reason)
    .bind(true)
    .execute(db)
    .await
    .context("Failed to log rotation started")?;

    tracing::info!(
        key_type = %key_type,
        old_key_id = ?old_key_id,
        new_key_id = %new_key_id,
        initiated_by = %initiated_by,
        reason = %reason,
        "Key rotation started"
    );

    Ok(())
}

/// Log rotation completed event
pub async fn log_rotation_completed(
    db: &DbPool,
    key_type: KeyType,
    new_key_id: &str,
    initiated_by: &str,
    duration_ms: i32,
) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO key_rotation_audit (
            key_type, new_key_id,
            event_type, initiated_by, success, duration_ms
        ) VALUES ($1, $2, $3, $4, $5, $6)
        "#,
    )
    .bind(key_type.to_string())
    .bind(new_key_id)
    .bind("rotation_completed")
    .bind(initiated_by)
    .bind(true)
    .bind(duration_ms)
    .execute(db)
    .await
    .context("Failed to log rotation completed")?;

    tracing::info!(
        key_type = %key_type,
        new_key_id = %new_key_id,
        duration_ms = duration_ms,
        "Key rotation completed"
    );

    Ok(())
}

/// Log rotation failed event
#[allow(dead_code)]
pub async fn log_rotation_failed(
    db: &DbPool,
    key_type: KeyType,
    initiated_by: &str,
    error_code: &str,
    error_message: &str,
    duration_ms: i32,
) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO key_rotation_audit (
            key_type, event_type, initiated_by,
            success, error_code, error_message, duration_ms
        ) VALUES ($1, $2, $3, $4, $5, $6, $7)
        "#,
    )
    .bind(key_type.to_string())
    .bind("rotation_failed")
    .bind(initiated_by)
    .bind(false)
    .bind(error_code)
    .bind(error_message)
    .bind(duration_ms)
    .execute(db)
    .await
    .context("Failed to log rotation failure")?;

    tracing::error!(
        key_type = %key_type,
        error_code = %error_code,
        error_message = %error_message,
        "Key rotation failed"
    );

    Ok(())
}

/// Log emergency key revocation
pub async fn log_emergency_revocation(
    db: &DbPool,
    key_id: &str,
    reason: &str,
    initiated_by: &str,
) -> Result<()> {
    // Get key type from key_id
    let key_type: Option<String> =
        sqlx::query_scalar("SELECT key_type FROM master_keys WHERE key_id = $1")
            .bind(key_id)
            .fetch_optional(db)
            .await?;

    let key_type = key_type.unwrap_or_else(|| "unknown".to_string());

    let metadata = serde_json::json!({
        "severity": "critical",
        "alert_sent": true,
        "requires_immediate_rotation": true
    });

    sqlx::query(
        r#"
        INSERT INTO key_rotation_audit (
            key_type, old_key_id,
            event_type, initiated_by, reason, success,
            metadata
        ) VALUES ($1, $2, $3, $4, $5, $6, $7)
        "#,
    )
    .bind(&key_type)
    .bind(key_id)
    .bind("emergency_revoke")
    .bind(initiated_by)
    .bind(reason)
    .bind(true)
    .bind(metadata)
    .execute(db)
    .await
    .context("Failed to log emergency revocation")?;

    tracing::warn!(
        key_id = %key_id,
        key_type = %key_type,
        reason = %reason,
        initiated_by = %initiated_by,
        "EMERGENCY KEY REVOCATION logged"
    );

    Ok(())
}

/// Log key access for monitoring and anomaly detection
#[allow(dead_code)]
pub async fn log_key_access(
    db: &DbPool,
    key_id: &str,
    operation: &str,
    service_name: &str,
    success: bool,
    error_code: Option<&str>,
) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO key_access_log (
            key_id, operation, service_name, success, error_code
        ) VALUES ($1, $2, $3, $4, $5)
        "#,
    )
    .bind(key_id)
    .bind(operation)
    .bind(service_name)
    .bind(success)
    .bind(error_code)
    .execute(db)
    .await
    .context("Failed to log key access")?;

    Ok(())
}

/// Get recent audit entries for a key type
#[allow(dead_code)]
pub async fn get_recent_audit_entries(
    db: &DbPool,
    key_type: KeyType,
    limit: i64,
) -> Result<Vec<AuditEntryRow>> {
    let entries: Vec<AuditEntryRow> = sqlx::query_as(
        r#"
        SELECT
            id,
            key_type,
            old_key_id,
            new_key_id,
            event_type,
            event_at,
            initiated_by,
            reason,
            success,
            error_code,
            error_message,
            duration_ms
        FROM key_rotation_audit
        WHERE key_type = $1
        ORDER BY event_at DESC
        LIMIT $2
        "#,
    )
    .bind(key_type.to_string())
    .bind(limit)
    .fetch_all(db)
    .await
    .context("Failed to fetch audit entries")?;

    Ok(entries)
}

/// Database row for audit entries
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AuditEntryRow {
    pub id: i64,
    pub key_type: String,
    pub old_key_id: Option<String>,
    pub new_key_id: Option<String>,
    pub event_type: String,
    pub event_at: DateTime<Utc>,
    pub initiated_by: String,
    pub reason: Option<String>,
    pub success: bool,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub duration_ms: Option<i32>,
}

/// Get key access statistics for anomaly detection
#[allow(dead_code)]
pub async fn get_access_stats(db: &DbPool, key_id: &str, hours: i32) -> Result<AccessStats> {
    let row: AccessStatsRow = sqlx::query_as(
        r#"
        SELECT
            COUNT(*)::BIGINT as total_count,
            COUNT(*) FILTER (WHERE success = true)::BIGINT as success_count,
            COUNT(*) FILTER (WHERE success = false)::BIGINT as failure_count,
            COUNT(DISTINCT service_name)::BIGINT as unique_services
        FROM key_access_log
        WHERE key_id = $1
          AND accessed_at > NOW() - ($2 || ' hours')::INTERVAL
        "#,
    )
    .bind(key_id)
    .bind(hours.to_string())
    .fetch_one(db)
    .await
    .context("Failed to fetch access stats")?;

    Ok(AccessStats {
        total_count: row.total_count.unwrap_or(0),
        success_count: row.success_count.unwrap_or(0),
        failure_count: row.failure_count.unwrap_or(0),
        unique_services: row.unique_services.unwrap_or(0),
    })
}

#[derive(Debug, sqlx::FromRow)]
struct AccessStatsRow {
    total_count: Option<i64>,
    success_count: Option<i64>,
    failure_count: Option<i64>,
    unique_services: Option<i64>,
}

/// Access statistics for a key
#[derive(Debug, Clone, Serialize)]
pub struct AccessStats {
    pub total_count: i64,
    pub success_count: i64,
    pub failure_count: i64,
    pub unique_services: i64,
}

impl AccessStats {
    /// Check if access pattern is anomalous
    #[allow(dead_code)]
    pub fn is_anomalous(&self, baseline_count: i64, threshold_multiplier: f64) -> bool {
        let threshold = (baseline_count as f64 * threshold_multiplier) as i64;
        self.total_count > threshold || self.failure_count > baseline_count / 10
    }
}

/// Alert on suspicious key access patterns
#[allow(dead_code)]
pub async fn check_and_alert_anomalies(
    db: &DbPool,
    key_id: &str,
    baseline_count: i64,
) -> Result<Option<String>> {
    let stats = get_access_stats(db, key_id, 1).await?;

    if stats.is_anomalous(baseline_count, 3.0) {
        let alert_message = format!(
            "Anomalous key access detected for {}: {} accesses in last hour ({} failures)",
            key_id, stats.total_count, stats.failure_count
        );

        tracing::warn!(
            key_id = %key_id,
            total_count = stats.total_count,
            failure_count = stats.failure_count,
            "Anomalous key access pattern detected"
        );

        // In production, send to alerting system (PagerDuty, Slack, etc.)
        // For now, just log and return the message

        return Ok(Some(alert_message));
    }

    Ok(None)
}
