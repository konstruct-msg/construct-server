//! Messaging abuse-control fail-open policy (P1-1 / P1-2).
//!
//! # Policy (launch)
//!
//! Prefer **availability** over hard-blocking when Redis (or related infra) is
//! unavailable for abuse controls. Delivery and anonymity take precedence;
//! degraded anti-spam is accepted and **must be metered**.
//!
//! Fail-**closed** paths (do not change lightly):
//! - Access-token blocklist / device-revoked check (auth)
//! - Privacy Pass under `MSG_STEALTH_TOKEN_POLICY=enforce` (incl. RedisError)
//! - Refresh-token rotate
//!
//! Fail-**open** paths (each increments `construct_msg_abuse_fail_open_total{control}`):
//!
//! | control              | Where                         | Effect when Redis/err        |
//! |----------------------|-------------------------------|------------------------------|
//! | `send_dedup`         | `grpc` SendMessage            | skip idempotency, may rate-inflate |
//! | `dispatch_dedup`     | `core` dispatch_envelope      | skip dedup mark/check        |
//! | `sentinel`           | `grpc` + `stream`             | allow send (ban/rate skipped)|
//! | `rate_trust`         | `grpc` trust/hourly/fanout    | TrustLevel::Trusted, no caps |
//! | `sealed_ip`          | `grpc` SendSealedMessage      | skip per-IP sealed limit     |
//! | `delivery_tag`       | `envelope` sealed replay      | deliver without tag check    |
//! | `federation_origin`  | `federation` origin RL        | skip per-origin limit        |
//!
//! # Alerts
//!
//! Alert if `sum(rate(construct_msg_abuse_fail_open_total[5m])) > 0` for sustained
//! windows — indicates Redis degradation or control bypass under load.
//!
//! # Product decision
//!
//! Tightening any row to fail-closed is a deliberate policy change (spam vs
//! outage). Do not flip without runbook + client backoff review.

// Module is documentation-only; metric helper lives in construct-metrics.
