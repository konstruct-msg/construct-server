// ============================================================================
// Message Delivery Operations
// ============================================================================
// Phase 2.8: Extracted from queue.rs for better organization
// Phase 4.6: Migrated to construct-redis for clean architecture

use anyhow::{Context, Result};
use construct_config::{Config, SECONDS_PER_DAY, SECONDS_PER_HOUR};
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
    ) -> Result<Vec<(String, Option<crate::kafka::types::KafkaMessageEnvelope>)>> {
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
                    tracing::debug!(
                        stream_id = %stream_id,
                        user_id = %user_id,
                        error = %e,
                        "Skipping unparseable Redis stream entry"
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
        // If client sends invalid format (e.g., UUID), reset to "0" to read from beginning
        let start_id = if let Some(id) = since_id {
            if Self::is_valid_stream_id(id) {
                id
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

        if entries.is_empty() {
            return Ok(vec![]);
        }

        // Convert StreamEntryBinary to Vec<(String, HashMap<String, Vec<u8>>)>
        let messages: Vec<(String, HashMap<String, Vec<u8>>)> = entries
            .into_iter()
            .map(|entry| (entry.id, entry.fields))
            .collect();

        // After reading new messages, delete old acknowledged messages from the stream
        // The since_id represents the last message ID the client received in the PREVIOUS request
        // This means the client is acknowledging receipt of all messages UP TO AND INCLUDING since_id
        //
        // IMPORTANT: We delete acknowledged messages (≤ since_id), NOT the newly read messages
        // This allows the client to process messages before they are deleted
        if let Some(ack_id) = since_id {
            // Use XTRIM with MINID to efficiently remove old messages
            // Format: XTRIM stream MINID <id> - keeps messages with ID >= id
            // We want to keep messages AFTER ack_id, so use next ID after ack_id

            let next_id_after_ack = if let Some((ts_str, seq_str)) = ack_id.split_once('-') {
                if let (Ok(ts), Ok(_seq)) = (ts_str.parse::<u64>(), seq_str.parse::<u64>()) {
                    // Next ID is either same timestamp with seq+1, or next timestamp with seq 0
                    // Since we don't know if there are more messages at same timestamp,
                    // use (timestamp+1)-0 to be safe
                    format!("{}-0", ts + 1)
                } else {
                    // Invalid format, skip deletion
                    tracing::warn!(stream_key = %stream_key, ack_id = %ack_id, "Invalid stream ID format");
                    return Ok(messages);
                }
            } else {
                tracing::warn!(stream_key = %stream_key, ack_id = %ack_id, "Invalid stream ID format (no dash)");
                return Ok(messages);
            };

            // Use raw Redis command for XTRIM MINID
            let trim_result: Result<i64, redis::RedisError> = redis::cmd("XTRIM")
                .arg(stream_key)
                .arg("MINID")
                .arg(&next_id_after_ack)
                .query_async(self.client.connection_mut())
                .await;

            match trim_result {
                Ok(deleted_count) => {
                    if deleted_count > 0 {
                        tracing::debug!(
                            stream_key = %stream_key,
                            ack_id = %ack_id,
                            min_id_kept = %next_id_after_ack,
                            deleted_count,
                            "Trimmed acknowledged messages from Redis stream"
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        stream_key = %stream_key,
                        ack_id = %ack_id,
                        "Failed to trim acknowledged messages from stream (non-fatal)"
                    );
                    // Non-fatal - messages will accumulate but delivery still works
                }
            }
        }

        Ok(messages)
    }

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

    /// Parse stream message fields into KafkaMessageEnvelope
    /// Filters by recipient_id to ensure user only gets their messages
    fn parse_stream_message(
        &self,
        fields: HashMap<String, Vec<u8>>,
        user_id: &str,
    ) -> Result<Option<crate::kafka::types::KafkaMessageEnvelope>> {
        // Extract message_id and payload from fields
        let message_id_bytes = fields
            .get("message_id")
            .ok_or_else(|| anyhow::anyhow!("Missing message_id in stream message"))?;
        let _message_id =
            String::from_utf8(message_id_bytes.clone()).context("Invalid UTF-8 in message_id")?;

        let payload = fields
            .get("payload")
            .ok_or_else(|| anyhow::anyhow!("Missing payload in stream message"))?;

        // Deserialize KafkaMessageEnvelope from MessagePack
        let envelope: crate::kafka::types::KafkaMessageEnvelope = rmp_serde::from_slice(payload)
            .context("Failed to deserialize KafkaMessageEnvelope from stream")?;

        // SECURITY: Filter by recipient_id - only return messages for this user
        if envelope.recipient_id != user_id {
            return Ok(None);
        }

        Ok(Some(envelope))
    }

    /// Subscribe to Redis Pub/Sub channel for message notifications
    ///
    /// OPTIMIZED: Simplified to avoid creating new Redis connections
    /// Instead of Pub/Sub (which requires new connection per request),
    /// we just sleep and let the client poll again
    /// This reduces Redis commands from ~100+ per long polling request to 0
    #[allow(dead_code)]
    pub(crate) async fn wait_for_message_notification(
        &self,
        _user_id: &str,
        timeout_ms: u64,
    ) -> Result<bool> {
        use tokio::time::Duration;

        // Simply sleep for the timeout duration
        // The client will poll again after timeout
        // This avoids creating new Redis Pub/Sub connections which was causing
        // thousands of Redis commands per second
        tokio::time::sleep(Duration::from_millis(timeout_ms)).await;

        // Always return false (timeout) - client will check for messages again
        // This is less efficient for real-time notifications but much better for Redis usage
        Ok(false)
    }

    /// Publishes a notification that a user has come online
    /// This triggers the Delivery Worker to process offline messages
    /// Phase 5: Track which server instance a user is connected to
    /// This allows delivery-worker to route messages directly to the correct server
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

    /// Process offline messages for a user when they come online
    /// Moves messages from {prefix}:offline:{user_id} to {prefix}:{server_instance_id}
    /// so they can be delivered via the delivery listener mechanism
    ///
    /// Messages are moved in FIFO order (oldest first) to maintain message ordering
    pub(crate) async fn process_offline_messages_for_user(
        &mut self,
        user_id: &str,
        server_instance_id: &str,
    ) -> Result<usize> {
        let offline_queue_key = format!("{}:offline:{}", self.delivery_queue_prefix, user_id);
        let delivery_queue_key = format!("{}:{}", self.delivery_queue_prefix, server_instance_id);

        // Use Lua script to atomically get all messages from offline queue and move to delivery queue
        // This ensures atomicity and maintains FIFO order
        let script = redis::Script::new(
            r"
            local offline_stream_key = KEYS[1]
            local delivery_list_key = KEYS[2]
            -- Read all messages from the stream
            local stream_messages = redis.call('XREAD', 'STREAMS', offline_stream_key, '0-0')
            local count = 0
            if stream_messages and #stream_messages > 0 then
                local messages = stream_messages[1][2]
                for i, stream_msg in ipairs(messages) do
                    -- stream_msg is [id, [field, value, field, value]]
                    local fields = stream_msg[2]
                    for j=1, #fields, 2 do
                        if fields[j] == 'payload' then
                            redis.call('RPUSH', delivery_list_key, fields[j+1])
                            count = count + 1
                        end
                    end
                end
                -- Delete the stream after processing
                redis.call('DEL', offline_stream_key)
            end
            return count
            ",
        );

        let message_count: usize = script
            .key(&offline_queue_key)
            .key(&delivery_queue_key)
            .invoke_async(self.client.connection_mut())
            .await?;

        if message_count > 0 {
            tracing::info!(
                user_id = %user_id,
                server_instance_id = %server_instance_id,
                message_count = message_count,
                "Processed offline messages for user - moved to delivery queue (FIFO order maintained)"
            );
        }

        Ok(message_count)
    }

    pub(crate) async fn publish_user_online(
        &mut self,
        user_id: &str,
        server_instance_id: &str,
        online_channel: &str,
    ) -> Result<()> {
        let notification = serde_json::json!({
            "user_id": user_id,
            "server_instance_id": server_instance_id,
        });

        let notification_str = notification.to_string();

        let _: () = self
            .client
            .connection_mut()
            .publish(online_channel, notification_str)
            .await?;

        tracing::debug!(
            user_id = %user_id,
            server_instance_id = %server_instance_id,
            channel = %online_channel,
            "Published user online notification"
        );

        Ok(())
    }

    /// Polls the delivery queue for this server instance
    /// Returns a list of message payloads (as bytes) that should be delivered
    pub(crate) async fn poll_delivery_queue(
        &mut self,
        server_instance_id: &str,
    ) -> Result<Vec<Vec<u8>>> {
        let key = format!("{}:{}", self.delivery_queue_prefix, server_instance_id);

        // Use Lua script to atomically get all messages and delete the queue
        // This replaces the loop of LMOVE operations with a single atomic operation
        let script = redis::Script::new(
            r"
            local messages = redis.call('LRANGE', KEYS[1], 0, -1)
            if #messages > 0 then
                redis.call('LTRIM', KEYS[1], 1, 0)
            end
            return messages
            ",
        );

        let messages: Vec<Vec<u8>> = script
            .key(&key)
            .invoke_async(self.client.connection_mut())
            .await?;

        // Filter out the empty placeholder message left by `register_server_instance`
        let filtered_messages: Vec<Vec<u8>> =
            messages.into_iter().filter(|msg| !msg.is_empty()).collect();

        if !filtered_messages.is_empty() {
            tracing::debug!(
                server_instance_id = %server_instance_id,
                count = filtered_messages.len(),
                "Polled delivery queue"
            );
        }

        Ok(filtered_messages)
    }

    /// Register this server instance in Redis
    /// Creates a delivery queue key with TTL to signal that this server is active
    /// delivery-worker uses KEYS delivery_queue:* to discover active servers
    pub(crate) async fn register_server_instance(
        &mut self,
        queue_key: &str,
        ttl_seconds: i64,
    ) -> Result<()> {
        tracing::debug!(queue_key = %queue_key, "Registering server instance");
        // Create an empty list (if doesn't exist) and set TTL
        // The heartbeat task will refresh this periodically

        // Check if key exists and its type
        let key_type: Option<String> = self.client.connection_mut().key_type(queue_key).await?;
        tracing::debug!(queue_key = %queue_key, key_type = ?key_type, "Checked key type");

        match key_type.as_deref() {
            // Key is already a list, do nothing.
            Some("list") => {
                tracing::debug!(queue_key = %queue_key, "Key is a list, doing nothing");
            }
            // Key doesn't exist (redis 'TYPE' returns 'none'), create it with a placeholder.
            Some("none") | None => {
                tracing::debug!(queue_key = %queue_key, "Key does not exist, creating it");
                self.client
                    .connection_mut()
                    .rpush::<_, _, ()>(queue_key, b"")
                    .await?;
            }
            // Key exists but has the wrong type, so delete and recreate it.
            Some(other_type) => {
                tracing::warn!(
                    queue_key = %queue_key,
                    key_type = %other_type,
                    "Delivery queue key has wrong type, deleting and recreating as list"
                );
                self.client.connection_mut().del::<_, ()>(queue_key).await?;
                self.client
                    .connection_mut()
                    .rpush::<_, _, ()>(queue_key, b"")
                    .await?;
            }
        }

        // Set/renew TTL
        self.client
            .connection_mut()
            .expire::<_, ()>(queue_key, ttl_seconds)
            .await?;
        tracing::debug!(queue_key = %queue_key, ttl = ttl_seconds, "Set TTL for key");

        Ok(())
    }

    /// Mark a message as delivered directly via tx.send() (fast path)
    /// УМНАЯ ДЕДУПЛИКАЦИЯ (Вариант D):
    ///
    /// После успешного tx.send() помечаем сообщение в Redis:
    /// SET delivered_direct:{message_id} 1 EX 3600
    ///
    /// delivery-worker перед доставкой проверяет:
    /// IF EXISTS delivered_direct:{message_id} → SKIP (уже доставлено)
    pub(crate) async fn mark_delivered_direct(&mut self, message_id: &str) -> Result<()> {
        let key = format!(
            "{}{}",
            self.config.redis_key_prefixes.delivered_direct, message_id
        );
        const DELIVERED_DIRECT_TTL: i64 = SECONDS_PER_HOUR; // 1 hour TTL

        self.client
            .connection_mut()
            .set_ex::<_, _, ()>(&key, "1", DELIVERED_DIRECT_TTL as u64)
            .await?;

        tracing::debug!(
            message_id = %message_id,
            ttl_seconds = DELIVERED_DIRECT_TTL,
            "Marked message as delivered directly (delivery-worker will skip)"
        );

        Ok(())
    }

    /// Check if a message was already delivered directly via tx.send()
    /// Used by delivery-worker to skip messages already delivered
    pub(crate) async fn is_delivered_direct(&mut self, message_id: &str) -> Result<bool> {
        let key = format!(
            "{}{}",
            self.config.redis_key_prefixes.delivered_direct, message_id
        );

        let exists: bool = self.client.exists(&key).await?;

        if exists {
            tracing::debug!(
                message_id = %message_id,
                "Message was already delivered directly - skipping delivery-worker delivery"
            );
        }

        Ok(exists)
    }

    /// Write a message directly to user's Redis stream (test mode only)
    ///
    /// This bypasses Kafka and writes directly to Redis, similar to what
    /// the delivery worker would do. Used only when Kafka is disabled.
    ///
    /// Stream format: {delivery_queue_prefix}:offline:{user_id}
    /// Fields: message_id (string), payload (MessagePack serialized envelope)
    pub(crate) async fn write_message_to_user_stream(
        &mut self,
        user_id: &str,
        envelope: &crate::kafka::types::KafkaMessageEnvelope,
    ) -> Result<String> {
        let stream_key = format!("{}:offline:{}", self.delivery_queue_prefix, user_id);

        // Serialize envelope to MessagePack (same as delivery worker)
        let payload = rmp_serde::to_vec(envelope)
            .context("Failed to serialize KafkaMessageEnvelope to MessagePack")?;

        // Use XADD with MAXLEN for automatic trimming
        let max_len = 10000_i64; // Same as delivery worker default

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

        tracing::debug!(
            stream_key = %stream_key,
            message_id = %envelope.message_id,
            stream_id = %stream_id,
            "Wrote message directly to user stream (test mode)"
        );

        Ok(stream_id)
    }
}
