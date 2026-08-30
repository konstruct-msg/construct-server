// ============================================================================
// Message Delivery Operations
// ============================================================================
// Phase 2.8: Extracted from queue.rs for better organization
// Phase 4.6: Migrated to construct-redis for clean architecture

use anyhow::{Context, Result};
use construct_config::{Config, SECONDS_PER_DAY};
use construct_redis::{RedisClient, StreamReadOptions};
use redis::AsyncCommands;
use std::collections::HashMap;

pub(crate) struct DeliveryManager<'a> {
    client: &'a mut RedisClient,
    config: &'a Config,
    delivery_queue_prefix: String,
}

impl<'a> DeliveryManager<'a> {
    pub(crate) fn new(
        client: &'a mut RedisClient,
        config: &'a Config,
        delivery_queue_prefix: String,
    ) -> Self {
        Self {
            client,
            config,
            delivery_queue_prefix,
        }
    }

    /// Approximate MAXLEN for every mailbox XADD. Server retention, not a
    /// per-sender quota — Redis cannot trim "this sender's entries".
    fn mailbox_maxlen(&self) -> i64 {
        self.config.messaging.queue_maxlen_standard.max(1)
    }

    /// Wake MessageStream subscribers after at least one XADD has landed.
    pub(crate) async fn publish_inbox_wakeup(&mut self, user_id: &str) {
        let wakeup_channel = format!("inbox:wakeup:{}", user_id);
        let _: std::result::Result<i64, _> = self
            .client
            .connection_mut()
            .publish(&wakeup_channel, "1")
            .await;
    }

    /// Read messages from Redis Stream for a user
    ///
    /// Reads from user-based stream: {delivery_queue_prefix}:offline:{user_id}
    ///
    /// ARCHITECTURE NOTE: We always use user-based streams to ensure reliable
    /// delivery in multi-instance deployments. The server_instance_id parameter
    /// is kept for API compatibility but ignored.
    pub(crate) async fn read_user_messages_from_stream(
        &mut self,
        user_id: &str,
        _server_instance_id: Option<&str>, // Ignored - kept for API compatibility
        since_id: Option<&str>,
        count: usize,
    ) -> Result<Vec<(String, Option<construct_message::types::MessageEnvelope>)>> {
        // Always read from user-based stream
        let stream_key = format!("{}:offline:{}", self.delivery_queue_prefix, user_id);

        let messages = self
            .read_stream_messages(&stream_key, since_id, count)
            .await?;

        // Parse messages. Unparseable entries return None so callers advance stream_id
        // past them without delivering garbage to the client.
        let mut result = Vec::new();
        for (stream_id, fields) in messages {
            match self.parse_stream_message(fields, user_id) {
                Ok(Some(envelope)) => result.push((stream_id, Some(envelope))),
                Ok(None) => result.push((stream_id, None)), // wrong recipient, still advance
                Err(e) => {
                    tracing::warn!(
                        stream_id = %stream_id,
                        user_id = %user_id,
                        error = %e,
                        "Skipping unparseable Redis stream entry (re-send message or DEL stream if written with broken to_vec)"
                    );
                    result.push((stream_id, None)); // advance past corrupt entry
                }
            }
        }

        Ok(result)
    }

    /// Read messages from a Redis Stream using XREAD
    async fn read_stream_messages(
        &mut self,
        stream_key: &str,
        since_id: Option<&str>,
        count: usize,
    ) -> Result<Vec<(String, HashMap<String, Vec<u8>>)>> {
        // Validate Redis Stream ID format: {timestamp}-{sequence} (e.g., "1707584371151-0")
        // Bare integer timestamps (e.g., "1772726016") are normalized to "{ts}-0".
        // If format is completely invalid (e.g., UUID), reset to "0".
        let normalized;
        let start_id = if let Some(id) = since_id {
            if let Some(norm) = Self::normalize_stream_id(id) {
                normalized = norm;
                normalized.as_str()
            } else {
                tracing::warn!(
                    stream_key = %stream_key,
                    invalid_id = %id,
                    "Invalid Redis Stream ID format - expected '{{timestamp}}-{{sequence}}', resetting to '0'"
                );
                "0"
            }
        } else {
            "0"
        };

        // Use construct-redis xread_binary for binary data (MessagePack)
        let options = StreamReadOptions {
            block: None,
            count: Some(count as u64),
        };

        let entries = match self
            .client
            .xread_binary(&[(stream_key, start_id)], options)
            .await
        {
            Ok(entries) => entries,
            Err(e) => {
                // Check if it's a "stream doesn't exist" error
                let err_str = e.to_string();
                if err_str.contains("no such key") || err_str.contains("WRONGTYPE") {
                    // Stream doesn't exist or is empty
                    return Ok(vec![]);
                } else {
                    return Err(anyhow::anyhow!("Failed to read stream: {}", e));
                }
            }
        };

        // NOTE: reads are intentionally side-effect free. Mailbox deletion is retention
        // only (XADD MAXLEN ~ + age sweep) — never by the server's read/send position
        // and never by a client-asserted since_cursor (silent-loss class; see
        // construct-docs decisions/minimal-server-delivery.md).

        if entries.is_empty() {
            return Ok(vec![]);
        }

        // Convert StreamEntryBinary to Vec<(String, HashMap<String, Vec<u8>>)>
        let messages: Vec<(String, HashMap<String, Vec<u8>>)> = entries
            .into_iter()
            .map(|entry| (entry.id, entry.fields))
            .collect();

        Ok(messages)
    }

    // `trim_offline_stream` (XTRIM MINID from a client-asserted cursor) was deleted with
    // minimal-server-delivery step 2. It is not "kept for ops": it is the exact operation
    // that produced the 2026-08-18 offline loss, and an unreachable copy of it is a
    // loaded gun that the next reader will assume is safe because it compiles. Mailbox
    // deletion is retention only — `MAXLEN ~` on XADD plus `trim_streams_by_age`.

    /// Validate Redis Stream ID format: {timestamp}-{sequence}
    /// Examples: "0", "1707584371151-0", "1707584371151-42"
    fn is_valid_stream_id(id: &str) -> bool {
        // Special IDs
        if id == "0" || id == "$" || id == "*" {
            return true;
        }

        // Check format: {timestamp}-{sequence}
        let parts: Vec<&str> = id.split('-').collect();
        if parts.len() != 2 {
            return false;
        }

        // Both parts must be valid numbers
        parts[0].parse::<u64>().is_ok() && parts[1].parse::<u64>().is_ok()
    }

    /// Normalize a Redis Stream ID. Bare u64 timestamps (e.g., "1772726016") are
    /// treated as "{timestamp}-0" per Redis convention.
    fn normalize_stream_id(id: &str) -> Option<String> {
        if Self::is_valid_stream_id(id) {
            return Some(id.to_string());
        }
        // Accept bare integer timestamps: "1772726016" → "1772726016-0"
        if id.parse::<u64>().is_ok() {
            return Some(format!("{}-0", id));
        }
        None
    }

    /// Parse stream message fields into MessageEnvelope
    /// Filters by recipient_id to ensure user only gets their messages
    fn parse_stream_message(
        &self,
        fields: HashMap<String, Vec<u8>>,
        user_id: &str,
    ) -> Result<Option<construct_message::types::MessageEnvelope>> {
        // Extract message_id and payload from fields
        let message_id_bytes = fields
            .get("message_id")
            .ok_or_else(|| anyhow::anyhow!("Missing message_id in stream message"))?;
        let _message_id =
            String::from_utf8(message_id_bytes.clone()).context("Invalid UTF-8 in message_id")?;

        let payload = fields
            .get("payload")
            .ok_or_else(|| anyhow::anyhow!("Missing payload in stream message"))?;

        // Deserialize MessageEnvelope from MessagePack
        let envelope: construct_message::types::MessageEnvelope = rmp_serde::from_slice(payload)
            .context("Failed to deserialize MessageEnvelope from stream")?;

        // SECURITY: Filter by recipient_id - only return messages for this user
        if envelope.recipient_id != user_id {
            return Ok(None);
        }

        Ok(Some(envelope))
    }

    /// Record which messaging instance owns this user's live MessageStream.
    /// Read back via `GET user:{user}:server_instance_id` (wake-push skip, not
    /// a delivery-worker hop — that worker is gone).
    pub(crate) async fn track_user_online(
        &mut self,
        user_id: &str,
        server_instance_id: &str,
    ) -> Result<()> {
        let key = format!(
            "{}{}:server_instance_id",
            self.config.redis_key_prefixes.user, user_id
        );
        // Set with TTL matching session TTL from config
        let ttl_seconds = self.config.session_ttl_days * SECONDS_PER_DAY;

        self.client
            .set_ex(&key, server_instance_id, ttl_seconds as u64)
            .await?;

        tracing::debug!(
            user_id = %user_id,
            server_instance_id = %server_instance_id,
            "Tracked user online status"
        );

        Ok(())
    }

    /// Phase 5: Remove user online tracking when they disconnect
    pub(crate) async fn untrack_user_online(&mut self, user_id: &str) -> Result<()> {
        let key = format!(
            "{}{}:server_instance_id",
            self.config.redis_key_prefixes.user, user_id
        );
        self.client.del(&key).await?;

        tracing::debug!(
            user_id = %user_id,
            "Removed user online tracking"
        );

        Ok(())
    }

    /// Phase 5: Get server instance ID for an online user
    pub(crate) async fn get_user_server_instance(
        &mut self,
        user_id: &str,
    ) -> Result<Option<String>> {
        let key = format!(
            "{}{}:server_instance_id",
            self.config.redis_key_prefixes.user, user_id
        );
        let result: Option<String> = self.client.get(&key).await?;
        Ok(result)
    }

    /// Write a message to the legacy user mailbox stream.
    ///
    /// Production path when `MSG_MAILBOX_USER_WRITE` is on. Caller
    /// (`write_message_to_device_streams`) publishes `inbox:wakeup` after this
    /// XADD (and any device writes) have landed.
    ///
    /// Stream format: {delivery_queue_prefix}:offline:{user_id}
    /// Fields: message_id (string), payload (MessagePack serialized envelope)
    pub(crate) async fn write_message_to_user_stream(
        &mut self,
        user_id: &str,
        envelope: &construct_message::types::MessageEnvelope,
    ) -> Result<String> {
        let stream_key = format!("{}:offline:{}", self.delivery_queue_prefix, user_id);

        // Serialize envelope to MessagePack (must match the XREAD path: to_vec_named).
        // rmp_serde::to_vec uses a legacy serializer that from_slice cannot read back
        // ("wrong msgpack marker Str8") — messages would be written but never delivered.
        let payload = rmp_serde::encode::to_vec_named(envelope)
            .context("Failed to serialize MessageEnvelope to MessagePack")?;

        // Recipient-stream retention — one cap for every writer. Sender trust
        // must never feed MAXLEN: Redis trims the whole inbox, not "this
        // sender's entries". New-account volume is hourly_limit_*, not a
        // smaller MAXLEN on someone else's mailbox.
        let max_len = self.mailbox_maxlen();

        let stream_id: String = redis::cmd("XADD")
            .arg(&stream_key)
            .arg("MAXLEN")
            .arg("~")
            .arg(max_len)
            .arg("*")
            .arg("message_id")
            .arg(&envelope.message_id)
            .arg("payload")
            .arg(&payload)
            .query_async(self.client.connection_mut())
            .await
            .context("Failed to write message to Redis stream")?;

        // INFO, not DEBUG, and not "(test mode)" — this is the production write path for every
        // offline message. The stream id it returns is the only thing that ties a dispatched
        // message to a position a later read can be checked against.
        //
        // On 2026-08-18 two messages were dispatched to an offline recipient, "Message
        // dispatched" was logged, and a poll from a cursor below them found nothing eleven
        // seconds later. Deciding whether they had ever been written took hours of reading code,
        // because the one line that knew was filtered out in production.
        tracing::info!(
            stream_key = %stream_key,
            message_id = %envelope.message_id,
            stream_id = %stream_id,
            "Wrote message to offline stream"
        );

        Ok(stream_id)
    }

    /// Write a message to a per-device Redis stream (multi-device fan-out).
    ///
    /// Stream format: {delivery_queue_prefix}:offline:{user_id}:{device_id}
    /// Clients that send `x-device-id` read from this stream instead of the
    /// user-level stream, enabling true per-device message isolation.
    pub(crate) async fn write_message_to_device_stream(
        &mut self,
        user_id: &str,
        device_id: &str,
        envelope: &construct_message::types::MessageEnvelope,
    ) -> Result<()> {
        let stream_key = format!(
            "{}:offline:{}:{}",
            self.delivery_queue_prefix, user_id, device_id
        );

        let payload = rmp_serde::encode::to_vec_named(envelope)
            .context("Failed to serialize MessageEnvelope to MessagePack")?;

        let max_len = self.mailbox_maxlen();
        let stream_id: String = redis::cmd("XADD")
            .arg(&stream_key)
            .arg("MAXLEN")
            .arg("~")
            .arg(max_len)
            .arg("*")
            .arg("message_id")
            .arg(&envelope.message_id)
            .arg("payload")
            .arg(&payload)
            .query_async(self.client.connection_mut())
            .await
            .context("Failed to write message to per-device stream")?;

        tracing::debug!(
            stream_key = %stream_key,
            message_id = %envelope.message_id,
            stream_id = %stream_id,
            device_id = %device_id,
            "Wrote message to per-device stream"
        );

        Ok(())
    }

    /// Read messages from a per-device Redis stream.
    ///
    /// Reads from: {delivery_queue_prefix}:offline:{user_id}:{device_id}
    /// Used by multi-device-aware clients that pass `x-device-id`.
    pub(crate) async fn read_device_messages_from_stream(
        &mut self,
        user_id: &str,
        device_id: &str,
        since_id: Option<&str>,
        count: usize,
    ) -> Result<Vec<(String, Option<construct_message::types::MessageEnvelope>)>> {
        let stream_key = format!(
            "{}:offline:{}:{}",
            self.delivery_queue_prefix, user_id, device_id
        );

        let messages = self
            .read_stream_messages(&stream_key, since_id, count)
            .await?;

        let mut result = Vec::new();
        for (stream_id, fields) in messages {
            match self.parse_stream_message(fields, user_id) {
                Ok(Some(envelope)) => result.push((stream_id, Some(envelope))),
                Ok(None) => result.push((stream_id, None)),
                Err(e) => {
                    tracing::debug!(
                        stream_id = %stream_id,
                        user_id = %user_id,
                        device_id = %device_id,
                        error = %e,
                        "Skipping unparseable entry in device stream"
                    );
                    result.push((stream_id, None));
                }
            }
        }

        Ok(result)
    }

    // ── Message deduplication ────────────────────────────────────────────────

    /// Returns true if `message_id` was already dispatched (duplicate).
    /// Uses a Redis key `msg:dedup:{message_id}` with 24h TTL.
    pub(crate) async fn is_message_duplicate(&mut self, message_id: &str) -> Result<bool> {
        let key = format!("msg:dedup:{}", message_id);
        let exists: bool = self.client.exists(&key).await?;
        Ok(exists)
    }

    /// Mark `message_id` as dispatched to prevent duplicate delivery.
    /// TTL 24h — covers any realistic client retry window.
    pub(crate) async fn mark_message_dispatched(&mut self, message_id: &str) -> Result<()> {
        const TTL_SECS: u64 = 24 * 60 * 60;
        let key = format!("msg:dedup:{}", message_id);
        self.client
            .set_ex(&key, "1", TTL_SECS)
            .await
            .context("Failed to mark message as dispatched")?;
        Ok(())
    }

    // ── Receipt routing ──────────────────────────────────────────────────────

    /// Store sender_id for a message so receipts can be routed back.
    /// Key: `receipt:sender:{message_id}` — TTL 30 days.
    pub(crate) async fn store_message_sender(
        &mut self,
        message_id: &str,
        sender_id: &str,
    ) -> Result<()> {
        const TTL_SECS: u64 = 30 * 24 * 60 * 60; // 30 days
        let key = format!("receipt:sender:{}", message_id);
        self.client
            .set_ex(&key, sender_id, TTL_SECS)
            .await
            .context("Failed to store message sender for receipt routing")?;
        Ok(())
    }

    /// Look up the original sender_id for a message_id.
    /// Returns `None` if the mapping has expired or never existed.
    pub(crate) async fn get_message_sender(&mut self, message_id: &str) -> Result<Option<String>> {
        let key = format!("receipt:sender:{}", message_id);
        let result: Option<String> = self.client.get(&key).await?;
        Ok(result)
    }

    /// Trim all offline message streams to remove entries older than `max_age_seconds`.
    ///
    /// Uses Redis SCAN to find all stream keys matching the offline queue pattern,
    /// then applies XTRIM MINID for time-based expiry.
    /// This is O(N) over total message count — run periodically (e.g., every 1 hour).
    pub(crate) async fn trim_streams_by_age(&mut self, max_age_seconds: u64) -> Result<u64> {
        use std::time::{SystemTime, UNIX_EPOCH};

        let cutoff_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("System time error")?
            .as_millis()
            .saturating_sub(max_age_seconds as u128 * 1000) as u64;

        // MINID format: "{milliseconds_timestamp}-0"
        let minid = format!("{}-0", cutoff_ms);
        let pattern = format!("{}:offline:*", self.delivery_queue_prefix);

        let mut cursor: u64 = 0;
        let mut total_trimmed: u64 = 0;

        loop {
            let (next_cursor, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(&pattern)
                .arg("COUNT")
                .arg(100u64)
                .query_async(self.client.connection_mut())
                .await
                .context("SCAN failed")?;

            for key in keys {
                let trimmed: i64 = redis::cmd("XTRIM")
                    .arg(&key)
                    .arg("MINID")
                    .arg(&minid)
                    .query_async(self.client.connection_mut())
                    .await
                    .unwrap_or(0);
                total_trimmed += trimmed as u64;
            }

            cursor = next_cursor;
            if cursor == 0 {
                break;
            }
        }

        Ok(total_trimmed)
    }

    /// Purge all messages from `sender_id` out of `recipient_id`'s Redis streams.
    ///
    /// Scans the user-level stream and all per-device streams for `recipient_id`,
    /// deserialises each MessagePack payload, and XDEL entries where the envelope
    /// `sender_id` matches.  Sealed-sender entries (empty `sender_id`) are skipped.
    ///
    /// Returns the total number of entries deleted.
    pub(crate) async fn purge_messages_from_sender(
        &mut self,
        recipient_id: &str,
        sender_id: &str,
    ) -> Result<u64> {
        let mut total: u64 = 0;

        // 1. User-level stream: {prefix}:offline:{recipient_id}
        let user_key = format!("{}:offline:{}", self.delivery_queue_prefix, recipient_id);
        total += self
            .purge_sender_from_one_stream(&user_key, sender_id)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(stream_key = %user_key, error = %e, "purge_messages_from_sender: failed on user stream");
                0
            });

        // 2. Per-device streams: {prefix}:offline:{recipient_id}:*
        let pattern = format!("{}:offline:{}:*", self.delivery_queue_prefix, recipient_id);
        let mut cursor: u64 = 0;
        loop {
            let (next_cursor, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(&pattern)
                .arg("COUNT")
                .arg(100u64)
                .query_async(self.client.connection_mut())
                .await
                .context("SCAN failed during purge_messages_from_sender")?;

            for key in keys {
                total += self
                    .purge_sender_from_one_stream(&key, sender_id)
                    .await
                    .unwrap_or_else(|e| {
                        tracing::warn!(stream_key = %key, error = %e, "purge_messages_from_sender: failed on device stream");
                        0
                    });
            }

            cursor = next_cursor;
            if cursor == 0 {
                break;
            }
        }

        Ok(total)
    }

    /// Scan a single stream and XDEL all entries whose `payload` decodes to an
    /// envelope with `sender_id` matching `target_sender_id`.
    async fn purge_sender_from_one_stream(
        &mut self,
        stream_key: &str,
        target_sender_id: &str,
    ) -> Result<u64> {
        use construct_message::types::MessageEnvelope;

        let entries = self
            .client
            .xrange_binary(stream_key, "-", "+")
            .await
            .context("XRANGE failed")?;

        if entries.is_empty() {
            return Ok(0);
        }

        let ids_to_delete: Vec<String> = entries
            .into_iter()
            .filter_map(|entry| {
                let payload = entry.fields.get("payload")?;
                let envelope: MessageEnvelope = rmp_serde::from_slice(payload).ok()?;
                // Skip sealed-sender entries — sender is intentionally hidden.
                if envelope.is_sealed_sender || envelope.sender_id.is_empty() {
                    return None;
                }
                if envelope.sender_id == target_sender_id {
                    Some(entry.id)
                } else {
                    None
                }
            })
            .collect();

        if ids_to_delete.is_empty() {
            return Ok(0);
        }

        let count = ids_to_delete.len() as u64;
        let mut cmd = redis::cmd("XDEL");
        cmd.arg(stream_key);
        for id in &ids_to_delete {
            cmd.arg(id.as_str());
        }
        let _: i64 = cmd
            .query_async(self.client.connection_mut())
            .await
            .context("XDEL failed")?;

        tracing::info!(
            stream_key = %stream_key,
            sender_id = %target_sender_id,
            deleted = count,
            "Purged queued messages from blocked sender"
        );
        Ok(count)
    }
}
