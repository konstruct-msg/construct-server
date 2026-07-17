#![allow(dead_code)]

use lazy_static::lazy_static;
use prometheus::{
    Histogram, IntCounter, IntGauge, register_histogram, register_int_counter, register_int_gauge,
};

lazy_static! {
    // ── MLS metrics ──
    static ref GROUPS_CREATED: IntCounter =
        register_int_counter!("mls_groups_created_total", "Total groups created").unwrap();
    static ref GROUPS_DISSOLVED: IntCounter =
        register_int_counter!("mls_groups_dissolved_total", "Total groups dissolved").unwrap();
    static ref GROUP_MESSAGES_SENT: IntCounter =
        register_int_counter!("mls_group_messages_sent_total", "Total group messages sent").unwrap();
    static ref GROUP_INVITES_SENT: IntCounter =
        register_int_counter!("mls_group_invites_sent_total", "Total group invites sent").unwrap();
    static ref COMMITS_SUBMITTED: IntCounter =
        register_int_counter!("mls_commits_submitted_total", "Total commits submitted").unwrap();
    static ref CLEANUP_DELETED: IntCounter =
        register_int_counter!("mls_cleanup_deleted_total", "Total items deleted by cleanup").unwrap();
    static ref ACTIVE_GROUPS: IntGauge =
        register_int_gauge!("mls_active_groups", "Current number of active groups").unwrap();
    static ref RATE_LIMIT_VIOLATIONS: IntCounter =
        register_int_counter!("mls_rate_limit_violations_total", "Rate limit violations").unwrap();
    static ref AUTH_FAILURES: IntCounter =
        register_int_counter!("mls_auth_failures_total", "Authentication failures").unwrap();
    static ref EPOCH_MISMATCHES: IntCounter =
        register_int_counter!("mls_epoch_mismatches_total", "Epoch mismatch errors").unwrap();
    static ref MESSAGE_DELIVERY_LATENCY: Histogram =
        register_histogram!("mls_message_delivery_latency_seconds", "Message delivery latency").unwrap();
    static ref GROUP_SIZE: Histogram =
        register_histogram!("mls_group_size", "Group size distribution").unwrap();

    // ── Channel metrics ──
    static ref CHANNELS_CREATED: IntCounter =
        register_int_counter!("channel_created_total", "Total channels created").unwrap();
    static ref CHANNELS_DELETED: IntCounter =
        register_int_counter!("channel_deleted_total", "Total channels deleted").unwrap();
    static ref CHANNEL_POSTS_PUBLISHED: IntCounter =
        register_int_counter!("channel_posts_published_total", "Total channel posts published").unwrap();
    static ref CHANNEL_SUBSCRIBERS_TOTAL: IntGauge =
        register_int_gauge!("channel_subscribers_total", "Total channel subscribers").unwrap();
    static ref CHANNEL_SUBSCRIBE_OPERATIONS: IntCounter =
        register_int_counter!("channel_subscribe_operations_total", "Total subscribe operations").unwrap();
    static ref CHANNEL_UNSUBSCRIBE_OPERATIONS: IntCounter =
        register_int_counter!("channel_unsubscribe_operations_total", "Total unsubscribe operations").unwrap();
    static ref CHANNEL_INVITE_LINKS_CREATED: IntCounter =
        register_int_counter!("channel_invite_links_created_total", "Total invite links created").unwrap();
    static ref CHANNEL_RATE_LIMIT_VIOLATIONS: IntCounter =
        register_int_counter!("channel_rate_limit_violations_total", "Channel rate limit violations").unwrap();
    static ref CHANNEL_POST_LATENCY: Histogram =
        register_histogram!("channel_post_publish_latency_seconds", "Post publish latency").unwrap();
}

// ── MLS metric functions ──

pub fn inc_groups_created() {
    GROUPS_CREATED.inc();
}
pub fn inc_groups_dissolved() {
    GROUPS_DISSOLVED.inc();
}
pub fn inc_group_messages_sent(count: u64) {
    GROUP_MESSAGES_SENT.inc_by(count);
}
pub fn inc_group_invites_sent(count: u64) {
    GROUP_INVITES_SENT.inc_by(count);
}
pub fn inc_commits_submitted() {
    COMMITS_SUBMITTED.inc();
}
pub fn inc_cleanup_operations(_operation: &'static str, deleted_count: i64) {
    CLEANUP_DELETED.inc_by(deleted_count as u64);
}
pub fn set_active_groups(count: i64) {
    ACTIVE_GROUPS.set(count);
}
pub fn inc_rate_limit_violations() {
    RATE_LIMIT_VIOLATIONS.inc();
}
pub fn inc_auth_failures() {
    AUTH_FAILURES.inc();
}
pub fn inc_epoch_mismatches() {
    EPOCH_MISMATCHES.inc();
}
pub fn observe_message_delivery_latency(latency_secs: f64) {
    MESSAGE_DELIVERY_LATENCY.observe(latency_secs);
}
pub fn observe_group_size(size: u64) {
    GROUP_SIZE.observe(size as f64);
}

// ── Channel metric functions ──

pub fn inc_channels_created() {
    CHANNELS_CREATED.inc();
}
pub fn inc_channels_deleted() {
    CHANNELS_DELETED.inc();
}
pub fn inc_channel_posts_published(count: u64) {
    CHANNEL_POSTS_PUBLISHED.inc_by(count);
}
pub fn set_channel_subscribers_total(count: i64) {
    CHANNEL_SUBSCRIBERS_TOTAL.set(count);
}
pub fn inc_channel_subscribe_operations() {
    CHANNEL_SUBSCRIBE_OPERATIONS.inc();
}
pub fn inc_channel_unsubscribe_operations() {
    CHANNEL_UNSUBSCRIBE_OPERATIONS.inc();
}
pub fn inc_channel_invite_links_created() {
    CHANNEL_INVITE_LINKS_CREATED.inc();
}
pub fn inc_channel_rate_limit_violations() {
    CHANNEL_RATE_LIMIT_VIOLATIONS.inc();
}
pub fn observe_channel_post_latency(latency_secs: f64) {
    CHANNEL_POST_LATENCY.observe(latency_secs);
}
