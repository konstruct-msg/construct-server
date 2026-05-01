//! Prometheus metrics for Channel service operations.

#![allow(dead_code)]

use lazy_static::lazy_static;
use prometheus::{
    register_histogram, register_int_counter, register_int_gauge, Histogram, IntCounter, IntGauge,
};

lazy_static! {
    static ref CHANNELS_CREATED: IntCounter =
        register_int_counter!("channel_created_total", "Total channels created").unwrap();
    static ref CHANNELS_DELETED: IntCounter =
        register_int_counter!("channel_deleted_total", "Total channels deleted").unwrap();
    static ref CHANNEL_POSTS_PUBLISHED: IntCounter = register_int_counter!(
        "channel_posts_published_total",
        "Total channel posts published"
    )
    .unwrap();
    static ref CHANNEL_SUBSCRIBERS_TOTAL: IntGauge =
        register_int_gauge!("channel_subscribers_total", "Total channel subscribers").unwrap();
    static ref CHANNEL_SUBSCRIBE_OPERATIONS: IntCounter = register_int_counter!(
        "channel_subscribe_operations_total",
        "Total subscribe operations"
    )
    .unwrap();
    static ref CHANNEL_UNSUBSCRIBE_OPERATIONS: IntCounter = register_int_counter!(
        "channel_unsubscribe_operations_total",
        "Total unsubscribe operations"
    )
    .unwrap();
    static ref CHANNEL_INVITE_LINKS_CREATED: IntCounter = register_int_counter!(
        "channel_invite_links_created_total",
        "Total invite links created"
    )
    .unwrap();
    static ref CHANNEL_RATE_LIMIT_VIOLATIONS: IntCounter = register_int_counter!(
        "channel_rate_limit_violations_total",
        "Channel rate limit violations"
    )
    .unwrap();
    static ref CHANNEL_POST_LATENCY: Histogram = register_histogram!(
        "channel_post_publish_latency_seconds",
        "Post publish latency"
    )
    .unwrap();
}

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
