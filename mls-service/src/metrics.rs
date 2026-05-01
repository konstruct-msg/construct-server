//! Prometheus metrics for MLS service operations.
//!
//! These functions are called from handlers to track operational metrics.
//! Some may be unused initially but are available for future integration.

#![allow(dead_code)]

use lazy_static::lazy_static;
use prometheus::{
    register_histogram, register_int_counter, register_int_gauge, Histogram, IntCounter, IntGauge,
};

lazy_static! {
    static ref GROUPS_CREATED: IntCounter =
        register_int_counter!("mls_groups_created_total", "Total groups created").unwrap();
    static ref GROUPS_DISSOLVED: IntCounter =
        register_int_counter!("mls_groups_dissolved_total", "Total groups dissolved").unwrap();
    static ref GROUP_MESSAGES_SENT: IntCounter =
        register_int_counter!("mls_group_messages_sent_total", "Total group messages sent")
            .unwrap();
    static ref GROUP_INVITES_SENT: IntCounter =
        register_int_counter!("mls_group_invites_sent_total", "Total group invites sent").unwrap();
    static ref COMMITS_SUBMITTED: IntCounter =
        register_int_counter!("mls_commits_submitted_total", "Total commits submitted").unwrap();
    static ref CLEANUP_DELETED: IntCounter = register_int_counter!(
        "mls_cleanup_deleted_total",
        "Total items deleted by cleanup"
    )
    .unwrap();
    static ref ACTIVE_GROUPS: IntGauge =
        register_int_gauge!("mls_active_groups", "Current number of active groups").unwrap();
    static ref RATE_LIMIT_VIOLATIONS: IntCounter =
        register_int_counter!("mls_rate_limit_violations_total", "Rate limit violations").unwrap();
    static ref AUTH_FAILURES: IntCounter =
        register_int_counter!("mls_auth_failures_total", "Authentication failures").unwrap();
    static ref EPOCH_MISMATCHES: IntCounter =
        register_int_counter!("mls_epoch_mismatches_total", "Epoch mismatch errors").unwrap();
    static ref MESSAGE_DELIVERY_LATENCY: Histogram = register_histogram!(
        "mls_message_delivery_latency_seconds",
        "Message delivery latency"
    )
    .unwrap();
    static ref GROUP_SIZE: Histogram =
        register_histogram!("mls_group_size", "Group size distribution").unwrap();
}

/// Counter: Total groups created
pub fn inc_groups_created() {
    GROUPS_CREATED.inc();
}

/// Counter: Total groups dissolved
pub fn inc_groups_dissolved() {
    GROUPS_DISSOLVED.inc();
}

/// Counter: Total group messages sent
pub fn inc_group_messages_sent(count: u64) {
    GROUP_MESSAGES_SENT.inc_by(count);
}

/// Counter: Total group invites sent
pub fn inc_group_invites_sent(count: u64) {
    GROUP_INVITES_SENT.inc_by(count);
}

/// Counter: Total commits submitted
pub fn inc_commits_submitted() {
    COMMITS_SUBMITTED.inc();
}

/// Counter: Total cleanup operations
pub fn inc_cleanup_operations(_operation: &'static str, deleted_count: i64) {
    CLEANUP_DELETED.inc_by(deleted_count as u64);
}

/// Gauge: Current number of active groups
pub fn set_active_groups(count: i64) {
    ACTIVE_GROUPS.set(count);
}

/// Counter: Rate limit violations
pub fn inc_rate_limit_violations() {
    RATE_LIMIT_VIOLATIONS.inc();
}

/// Counter: Authentication failures
pub fn inc_auth_failures() {
    AUTH_FAILURES.inc();
}

/// Counter: Epoch mismatches (stale client attempts)
pub fn inc_epoch_mismatches() {
    EPOCH_MISMATCHES.inc();
}

/// Histogram: Group message delivery latency (seconds)
pub fn observe_message_delivery_latency(latency_secs: f64) {
    MESSAGE_DELIVERY_LATENCY.observe(latency_secs);
}

/// Histogram: Group size distribution
pub fn observe_group_size(size: u64) {
    GROUP_SIZE.observe(size as f64);
}
