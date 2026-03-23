# Push Notification System Audit - Construct Server (Rust gRPC)

## EXECUTIVE SUMMARY

**Verdict: ⚠️ BETA QUALITY - Unsafe for Production Without Critical Fixes**

The push notification system has a **solid architecture with strong privacy guarantees**, but suffers from **critical production bugs** that cause **silent notification failures** when APNS is unavailable or tokens become invalid.

---

## 1. DEVICE TOKEN REGISTRATION (registerDeviceToken RPC)

### Handler Locations
- **gRPC Handler**: `/notification-service/src/main.rs:96-135`
- **Business Logic**: `/notification-service/src/core.rs:247-383`
- **RPC Definition**: `/shared/proto/services/notification_service.proto:54-82`

### Flow
```
Client → RegisterDeviceTokenRequest
  ├─ Extract user_id from x-user-id gRPC metadata
  ├─ Validate token (1-128 chars)
  ├─ AES-256 encrypt device token
  ├─ Create token hash for deduplication
  └─ INSERT OR UPDATE device_tokens table
       ├─ ON CONFLICT (user_id, device_id) → update (modern path)
       └─ ON CONFLICT (user_id, device_token_hash) → update (legacy)
```

### Database Storage
**Table**: `device_tokens` (encrypted, indexed)
```sql
CREATE TABLE device_tokens (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL,
    device_token_hash BYTEA NOT NULL,        -- Hash for dedup
    device_token_encrypted BYTEA NOT NULL,   -- AES-256 encrypted APNS token
    device_name_encrypted BYTEA,             -- Optional: user's device name
    notification_filter TEXT DEFAULT 'silent', -- Filter type
    enabled BOOLEAN DEFAULT TRUE,
    created_date DATE NOT NULL,
    device_id TEXT,                          -- iOS Keychain ID (for upsert)
    push_provider TEXT DEFAULT 'apns',       -- 'apns' or 'fcm'
    push_environment TEXT DEFAULT 'sandbox', -- 'sandbox' or 'production'
    
    UNIQUE(user_id, device_token_hash),
    UNIQUE(user_id, device_id) WHERE device_id IS NOT NULL
);
```

### Upsert Strategy
- **With device_id** (modern iOS): Updates existing row when token rotates → no duplicates
- **Without device_id** (legacy): Updates on token hash collision → idempotent

### Token Loss Risk Assessment
✅ **NO RISK OF TOKEN LOSS**
- `ON CONFLICT` ensures idempotent upsert (transaction atomic)
- If DB insert fails → gRPC returns error → client can safely retry
- Even 10 retries result in same final state (atomic transaction)

---

## 2. PUSH NOTIFICATION SENDING

### Path A: Explicit RPC (notification-service)
**File**: `/notification-service/src/core.rs:102-244`
**RPC**: `SendBlindNotification(user_id, badge_count, activity_type)`

**Process**:
```
1. Query all enabled device_tokens for user_id from DB
2. For each token:
   a. Decrypt token (AES-256)
   b. Check notification_filter
      - 'silent' → background push (no alert)
      - 'visible_all'/'visible_dm'/'visible_mentions'/'visible_contacts' → show alert
   c. Send via APNS client
   d. If error: LOG, CONTINUE to next token (NO RETRY)
3. Return success if ANY device succeeded
```

### Path B: Auto-trigger on Message Arrival (messaging-service)
**File**: `/messaging-service/src/core.rs:170-255`
**Trigger**: Called during `dispatch_envelope()` (message dispatch)

**Process**:
```
1. Check if APNS enabled
2. tokio::spawn(async { send_push_notification(...) })
   a. Fire-and-forget (non-blocking)
   b. Query device_tokens from DB
   c. Decrypt, send silent push to each device
   d. If error: LOG WARNING, swallow error
3. Continue message delivery regardless of push result
```

### Supported Providers
| Provider | Status | Implementation |
|----------|--------|-----------------|
| **APNS** (iOS) | ✅ Full | `/crates/construct-apns/src/client.rs` (213 lines) |
| **FCM** (Android) | ❌ Stub | Proto fields exist but NOT implemented |

### APNS Client Details
**File**: `/crates/construct-apns/src/client.rs`

**Initialization**:
```rust
let apns_client = Arc::new(ApnsClient::new(config.apns.clone())?);
if let Err(e) = apns_client.initialize().await {
    if config.apns.enabled {
        tracing::error!("APNs initialization failed — push notifications DISABLED");
        // → Service starts but push silently disabled
    }
}
```

**Send Logic** (`client.rs:77-173`):
- Requires `apns-push-type` header (iOS 13+ requirement)
- **Silent**: Background push, no alert, low priority
- **Visible**: Alert with generic title/body, sound, high priority
- Attaches custom `construct` data for app to handle

---

## 3. DELIVERY-WORKER (NOT a Push Sender)

**Important**: Delivery-worker is **purely a message router**, NOT a push notification sender.

**Purpose**: Route offline messages from Kafka → Redis Streams for later pickup

**Files**: 
- `/delivery-worker/src/main.rs` — Entry point
- `/delivery-worker/src/processor.rs` — Message routing
- `/delivery-worker/src/deduplication.rs` — Prevent duplicates
- `/delivery-worker/src/dlq.rs` — Dead letter queue
- `/delivery-worker/src/retry.rs` — Retry logic

**What It Does NOT Do**:
- ❌ Send push notifications
- ❌ Call APNS/FCM
- ❌ Call notification-service

**Offset Management** (Kafka as source of truth):
```
USER OFFLINE:
  1. Store message in Redis Stream
  2. DO NOT commit Kafka offset
  3. When user comes online → automatic Kafka redelivery

USER ONLINE:
  1. Push to delivery_stream:{server_instance_id}
  2. Commit Kafka offset
  3. Message considered delivered
```

**Error Handling**:
- Redis errors: Retry 3x with exponential backoff (100ms → 800ms)
- Processing errors: Track retry count (max 5) → DLQ
- DLQ: Log structured JSON to stderr (TODO: send to Kafka)

---

## 4. NOTIFICATION-SERVICE RESPONSIBILITIES

**Directory**: `/notification-service/src/`

### What It Does
1. **Device Token Registration**
   - `registerDeviceToken()` — Register with encryption
   - `unregisterDeviceToken()` — Deregister
   - `updateNotificationPreferences()` — Change filter/enabled status

2. **Push Sending**
   - `sendBlindNotification()` — Explicit push RPC

3. **Infrastructure**
   - Initialize APNS client (load .p8 key)
   - Initialize device token encryption
   - Manage gRPC server

### What It Does NOT Do
- ❌ Listen for message arrivals (messaging-service does that)
- ❌ Store message content (privacy-first design)
- ❌ Track notification delivery status
- ❌ **Implement retry for failed sends** ← CRITICAL BUG

---

## 5. RETRY MECHANISMS (CRITICAL FINDINGS)

### Summary: ZERO RETRY for Push Notifications

**Level 1: notification-service Send Loop**
```rust
for token_row in &device_tokens {
    match context.apns_client.send_notification(...).await {
        Err(e) => {
            tracing::error!("Failed to send APNs notification");
            continue;  // ← One attempt only, NO RETRY
        }
        Ok(_) => sent_count += 1,
    }
}
```

**Level 2: APNS Client**
```rust
match client.send(built).await {
    Err(e) => {
        warn!("APNs error: {}", e);
        // TODO: Parse error response and handle invalid tokens
        Err(e.into())  // ← One attempt, return error
    }
}
```

**Level 3: Messaging Service Background Task**
```rust
tokio::spawn(async move {
    if let Err(e) = send_push_notification(&ctx, &recipient).await {
        tracing::warn!("Failed to send push (non-critical)");
    }  // ← Fire-and-forget, errors completely swallowed
});
```

**Level 4: Delivery Worker (Message Delivery Only)**
- Redis-backed retry counter
- MAX_RETRIES = 5 with exponential backoff
- **Does NOT affect push notifications** (only message delivery)

### Impact
**If APNS is temporarily down for 1-5 seconds → ALL notifications silently dropped**

---

## 6. TOKEN LOSS ON registerDeviceToken FAILURE

### Happy Path
- DB insert succeeds → gRPC returns `success: true` with `token_id`
- Client receives success, registration complete

### Failure Path
- DB insert fails with error → gRPC returns error to client
- Encrypted token in memory is discarded
- **Token is either fully stored OR not stored at all** (atomic transaction)

### If gRPC Stream Closes Before Response
- Encrypted token lost from memory (on-disk unchanged)
- Client receives connection error
- **Client should retry with same token**
- On retry: `ON CONFLICT` clause updates existing row (idempotent)

### Assessment
✅ **NO TOKEN LOSS RISK**
- `ON CONFLICT` ensures idempotent upsert
- Atomic transaction (all-or-nothing)
- Safe for retries (same final state regardless)

---

## 7. CRITICAL BUGS & ISSUES

### 🔴 CRITICAL BUG #1: No Retry on APNS Failures

**Location**: 
- `/notification-service/src/core.rs:219-230`
- `/messaging-service/src/core.rs:232-240`

**Code**:
```rust
if let Err(e) = context.apns_client.send_notification(...).await {
    tracing::error!("Failed to send APNs notification");
    continue;  // ← Silently skip — NO RETRY
}
```

**Scenario**: APNS API down 1-5 seconds
**Result**: ALL pending notifications SILENTLY DROPPED

**Impact**: 
- Users miss critical notifications
- No error to client (async task)
- Only visible in logs (hard to monitor)

**Severity**: **CRITICAL**

**Fix**: Implement 3-attempt exponential backoff
```rust
const RETRIES: [u64; 3] = [100, 300, 900]; // milliseconds
for (attempt, delay) in RETRIES.iter().enumerate() {
    match context.apns_client.send_notification(...).await {
        Ok(_) => { sent_count += 1; break; }
        Err(e) if attempt < 2 => {
            tokio::time::sleep(Duration::from_millis(*delay)).await;
        }
        Err(e) => {
            tracing::error!("APNs failed after {} retries", attempt + 1);
        }
    }
}
```

---

### 🔴 CRITICAL BUG #2: Invalid Tokens Not Cleaned Up

**Location**: `/crates/construct-apns/src/client.rs:168-170`

**Code**:
```rust
// Check if error indicates invalid token
// Note: apns-h2 error handling - check ErrorReason for BadDeviceToken
warn!("APNs error (may indicate invalid token): {}", e);
// TODO: Parse error response and handle invalid tokens
// TODO: Check if e contains ErrorReason::BadDeviceToken

Err(e.into())
```

**Scenario**:
1. User uninstalls app
2. Server sends push with that token
3. APNS returns `BadDeviceToken` error
4. Error is logged but **token remains in DB with `enabled=TRUE`**
5. Next message → APNS call wasted with same dead token
6. Pattern repeats → wasted APNS quota

**Impact**:
- Accumulating dead tokens in DB (garbage data)
- Wasted APNS API calls
- Performance degradation
- Exhausts APNS rate limits

**Severity**: **CRITICAL**

**Fix**: Parse APNS error and disable invalid tokens
```rust
match client.send(built).await {
    Ok(_response) => Ok(()),
    Err(e) => {
        // Check for BadDeviceToken error
        if let Some(error_reason) = parse_apns_error(&e) {
            if error_reason == ErrorReason::BadDeviceToken {
                // Mark token as disabled
                sqlx::query("UPDATE device_tokens SET enabled=FALSE WHERE token_hash=$1")
                    .bind(token_hash)
                    .execute(&db_pool)
                    .await?;
            }
        }
        Err(e.into())
    }
}
```

---

### 🟡 MEDIUM BUG #3: FCM Not Implemented

**Location**: 
- `/notification-service/src/core.rs:38`
- `/shared/proto/notification_service.proto:69`

**Issue**:
- Proto supports FCM (`push_provider` field)
- Tokens stored with `push_provider='fcm'`
- **No actual FCM implementation**
- Android devices → register token → **push NEVER SENT**

**Code**:
```rust
pub push_provider: String,    // "apns" | "fcm"
push_provider: match req.provider {
    2 => "fcm".to_string(),
    _ => "apns".to_string(),  // default
},
```

**Impact**: Silent failure for Android platforms

**Severity**: **MEDIUM** (affects future Android)

**Fix**: Either implement FCM or remove from proto

---

### 🟡 MEDIUM BUG #4: Messaging Service Push Errors Swallowed

**Location**: `/messaging-service/src/core.rs:176-180`

**Code**:
```rust
tokio::spawn(async move {
    if let Err(e) = send_push_notification(&ctx, &recipient).await {
        tracing::warn!(error = %e, "Failed to send push notification (non-critical)");
    }
});
```

**Note**: This is intentional (message delivery is primary, push is secondary)

**Severity**: **MEDIUM** (design choice, affects latency not correctness)

---

### 🟡 MEDIUM BUG #5: Missing APNs Readiness Check

**Location**: `/notification-service/src/main.rs:234-251`

**Issue**: Missing APNs .p8 key file
```rust
if let Err(e) = apns_client.initialize().await {
    if config.apns.enabled {
        tracing::error!(
            error = %e,
            key_path = %config.apns.key_path,
            "APNs initialization failed — push notifications DISABLED"
        );
    }
    // Service continues to start! ← Operator may not notice
}
```

**Impact**: Push silently disabled with only log message

**Severity**: **MEDIUM** (operational issue)

**Fix**: Fail `/health/ready` check if key missing and APNS_ENABLED=true

---

### 🟢 MINOR: DLQ Not Sent to Kafka

**Location**: `/delivery-worker/src/dlq.rs:131-146`

**Code**:
```rust
// TODO: Add DLQ-specific topic support to MessageProducer to actually send to Kafka.
let _ = producer;

// For now: serialize DLQ message to structured log (stderr)
error!(
    target: "dlq",
    message_id = %envelope.message_id,
    payload = %serde_json::to_string(&dlq_message).unwrap_or_default(),
    "DLQ_MESSAGE: Message moved to dead letter queue"
);
```

**Impact**: Failed messages logged but not persisted to Kafka

**Workaround**: Ops can grep logs for "DLQ_MESSAGE"

**Severity**: **MINOR** (fallback works, future optimization)

---

## 8. DATABASE SCHEMA

### device_tokens Table
**Migrations**:
1. `006_device_tokens.sql` — Initial (encryption, hashing)
2. `025_device_tokens_v2.sql` — Add device_id, provider, environment

**Indexes**:
- `idx_device_tokens_user_enabled` — user_id + enabled=TRUE
- `idx_device_tokens_hash` — Token hash lookups
- `idx_device_tokens_user_device_id` — (user_id, device_id) upsert key
- `idx_device_tokens_env` — Environment filtering

**Privacy Features** ✅:
- Tokens encrypted before storage
- Device names encrypted
- No timestamps with time component
- No activity tracking
- No PII in notifications

---

## 9. ERROR HANDLING MATRIX

| Component | Silent Failures? | Severity |
|-----------|-----------------|----------|
| registerDeviceToken DB error | No (gRPC error) | N/A |
| APNS send failure | ✅ YES | **CRITICAL** |
| Invalid token handling | ✅ YES | **CRITICAL** |
| Messaging service push task | ✅ YES (by design) | MEDIUM |
| FCM not implemented | ✅ YES | MEDIUM |
| APNs key not found | ✅ YES (logged) | MEDIUM |
| DLQ not sent to Kafka | ✅ YES (logged to stderr) | MINOR |

---

## 10. PRODUCTION READINESS ASSESSMENT

### What Works Well ✅
1. **Token Registration** — Atomic, encrypted, idempotent
2. **Database Design** — Privacy-first with proper encryption
3. **Notification Routing** — Correct online/offline handling
4. **Message Delivery** — Kafka source of truth
5. **Multi-Environment** — Sandbox/production separation
6. **Device ID Handling** — Proper upsert on token rotation

### What Fails Silently ❌
1. **APNS Temporary Failures** — Notifications lost
2. **Invalid Tokens** — Accumulate in DB
3. **FCM** — Tokens registered but never sent
4. **No Retry Logic** — Single attempt only

### Production Status
| Aspect | Status | Notes |
|--------|--------|-------|
| **iOS Notifications** | ⚠️ Degraded | Works but fragile — no retry |
| **Android Support** | ❌ Not Ready | FCM stub |
| **High Availability** | ⚠️ Medium | Depends on APNS reliability |
| **Observability** | ⚠️ Medium | Errors logged but not metrics-friendly |

### Overall Verdict
**⚠️ BETA QUALITY**
- ✅ Safe for: Development, Testing
- ⚠️ Risky for: Production (without critical fixes)

---

## 11. RECOMMENDED FIXES (Priority Order)

### CRITICAL (Do First)
1. **Add APNS Retry Logic**
   - Location: `/crates/construct-apns/src/client.rs:send_notification()`
   - Implementation: 3 attempts with exponential backoff (100ms, 300ms, 900ms)
   - Impact: Prevents notification loss during APNS hiccups

2. **Implement Invalid Token Cleanup**
   - Location: `/notification-service/src/core.rs` + `/messaging-service/src/core.rs`
   - Implementation: Parse APNS error for BadDeviceToken, set `enabled=FALSE`
   - Impact: Prevents accumulation of dead tokens

### HIGH (Do Next)
3. **Implement FCM OR Disable FCM UI**
   - Currently tokens registered but silently ignored
   - Choose: Either implement FCM or remove from proto

4. **Add Prometheus Metrics**
   - Track push send failures
   - Alert if >5% of sends fail

### MEDIUM (Polish)
5. **Send DLQ to Kafka**
   - True persistent dead letter queue
   - Replace stderr logging with Kafka topic

6. **Add APNs Readiness Check**
   - `/health/ready` fails if key missing and APNS_ENABLED=true

---

## 12. KEY FILES & CODE LOCATIONS

### Notification Service
- `/notification-service/src/main.rs` — gRPC server, APNS init
- `/notification-service/src/core.rs` — Business logic
- `/notification-service/src/handlers.rs` — Empty (delegated)

### APNS Implementation
- `/crates/construct-apns/src/client.rs` — Main client (213 lines)
- `/crates/construct-apns/src/lib.rs` — Public exports
- `/crates/construct-apns/src/types.rs` — Payload types

### Messaging Service
- `/messaging-service/src/core.rs:170-255` — Push trigger
- `/messaging-service/src/context.rs` — APNS client context

### Delivery Worker
- `/delivery-worker/src/main.rs` — Entry point
- `/delivery-worker/src/processor.rs` — Message routing
- `/delivery-worker/src/retry.rs` — Retry logic
- `/delivery-worker/src/dlq.rs` — Dead letter queue

### Database
- `/shared/migrations/006_device_tokens.sql` — Table schema
- `/shared/migrations/025_device_tokens_v2.sql` — v2 enhancements

### Protocol
- `/shared/proto/services/notification_service.proto` — RPC definitions

---

## CONCLUSION

The push notification system is **architecturally sound** with strong privacy design, but has **critical bugs** that cause **silent failures** in production scenarios. The two main issues are:

1. **No retry logic** — APNS temporary failures = lost notifications
2. **Invalid token cleanup missing** — Dead tokens accumulate and waste quota

**Recommendation**: Implement the 2 critical fixes before production deployment. Current system is suitable only for development/testing.
