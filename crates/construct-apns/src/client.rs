use anyhow::Context;
use anyhow::Result;
use apns_h2::{
    Client, ClientConfig, CollapseId, DefaultNotificationBuilder, Endpoint, NotificationBuilder,
    NotificationOptions, Priority, PushType as ApnsPushType, error::Error as ApnsH2Error,
    response::ErrorReason,
};
use hex;
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use super::types::{AlertData, ApnsPayload, NotificationPriority, PushType};
use construct_config::{ApnsConfig, ApnsEnvironment};

/// Error type returned by APNs send operations.
///
/// Callers MUST handle `InvalidToken` by disabling the token in the database —
/// APNs will never accept it again until the device re-registers.
#[derive(Debug, Error)]
pub enum ApnsSendError {
    /// APNs rejected the device token (`BadDeviceToken` or `Unregistered`).
    ///
    /// The token is permanently invalid. Caller should set `enabled = false`
    /// on the `device_tokens` row so we stop hammering APNs with dead tokens.
    #[error("APNs: device token is invalid or unregistered")]
    InvalidToken,

    /// Any other APNs or infrastructure error.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Does this APNs answer condemn the *device* token — the one verdict that lets a caller delete
/// or disable it?
///
/// Only an explicit `BadDeviceToken` (400) or `Unregistered` (410) does. A 403 never does,
/// whatever reason it carries: 403 is APNs judging the *provider* (Expired/Invalid/Missing
/// ProviderToken, Forbidden, BadCertificate*), and treating it as a verdict on the device turned a
/// provider-auth outage into deleting every token it touched (`938f395`). No body, no verdict.
///
/// Pure so the rule can be pinned by a table test without a live APNs client.
pub(crate) fn condemns_device_token(code: u16, reason: Option<&ErrorReason>) -> bool {
    code != 403
        && matches!(
            reason,
            Some(ErrorReason::BadDeviceToken | ErrorReason::Unregistered)
        )
}

/// APNs client wrapper
#[derive(Clone)]
pub struct ApnsClient {
    client: Arc<RwLock<Option<Client>>>,
    config: ApnsConfig,
}

impl ApnsClient {
    /// Create new APNs client
    pub fn new(config: ApnsConfig) -> Result<Self> {
        Ok(Self {
            client: Arc::new(RwLock::new(None)),
            config,
        })
    }

    /// Initialize APNs client (loads key from file)
    pub async fn initialize(&self) -> Result<()> {
        if !self.config.enabled {
            info!("APNs is disabled - skipping initialization");
            return Ok(());
        }

        info!(
            "Initializing APNs client (environment: {:?})",
            self.config.environment
        );

        // Surface VoIP topic configuration at boot — when this is empty, VoIP pushes are
        // silently skipped (incoming calls never wake a backgrounded device). Make it visible.
        match self.config.voip_topic.as_deref() {
            Some(topic) if !topic.is_empty() => {
                info!("APNs VoIP topic configured: {}", topic);
            }
            _ => {
                warn!(
                    "APNs VoIP topic is NOT configured (set APNS_VOIP_TOPIC=<bundle_id>.voip) — \
                     VoIP incoming-call pushes will be SKIPPED"
                );
            }
        }

        // Open .p8 key file
        let key_file = File::open(&self.config.key_path)
            .with_context(|| format!("Failed to open APNs key file: {}", self.config.key_path))?;
        let mut key_reader = BufReader::new(key_file);

        // Determine endpoint (production or sandbox)
        let endpoint = match self.config.environment {
            ApnsEnvironment::Production => Endpoint::Production,
            ApnsEnvironment::Development => Endpoint::Sandbox,
        };

        let client_config = ClientConfig::new(endpoint);

        // Create client using token-based authentication
        let client = Client::token(
            &mut key_reader,
            &self.config.key_id,
            &self.config.team_id,
            client_config,
        )
        .with_context(|| "Failed to create APNs client")?;

        *self.client.write().await = Some(client);

        info!(
            "APNs client initialized successfully (key_id: {}, team_id: {})",
            self.config.key_id, self.config.team_id
        );

        Ok(())
    }

    /// Send push notification to device.
    ///
    /// Returns `Err(ApnsSendError::InvalidToken)` when APNs signals the token is
    /// permanently invalid — caller should disable it in the database.
    pub async fn send_notification(
        &self,
        device_token: &str,
        payload: ApnsPayload,
        push_type: PushType,
        priority: NotificationPriority,
    ) -> Result<(), ApnsSendError> {
        if !self.config.enabled {
            debug!("APNs disabled - skipping notification send");
            return Ok(());
        }

        let client_guard = self.client.read().await;
        let client = client_guard
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("APNs client not initialized"))?;

        // Serialize payload
        let payload_json =
            serde_json::to_string(&payload).with_context(|| "Failed to serialize APNs payload")?;

        // SECURITY: Hash device token for logging (never log full token)
        use crate::DeviceTokenEncryption;
        let token_hash_bytes = DeviceTokenEncryption::hash_token(device_token);
        let token_hash_hex = hex::encode(&token_hash_bytes);
        debug!(
            "Sending APNs notification: device_token_hash={}, push_type={:?}, priority={:?}",
            &token_hash_hex[..8],
            push_type,
            priority
        );
        debug!("APNs payload: {}", payload_json);

        let topic = topic_for(&self.config, push_type);

        let options = notification_options(topic, push_type, priority, &payload);

        // Build notification based on push type.
        // BUG FIX: previously the `payload` parameter was ignored entirely and
        // a hardcoded DefaultNotificationBuilder was used for all cases.
        let mut built = match push_type {
            PushType::Silent => {
                // Background push: content-available = 1, no alert, no sound
                DefaultNotificationBuilder::new()
                    .content_available()
                    .build(device_token, options)
            }
            PushType::Visible => {
                // Alert from payload; fall back to generic strings (privacy-safe).
                let builder = match payload.aps.alert {
                    Some(AlertData::Localized {
                        title_loc_key,
                        loc_key,
                    }) => DefaultNotificationBuilder::new()
                        .title_loc_key(title_loc_key)
                        .loc_key(loc_key),
                    Some(AlertData::Text {
                        ref title,
                        ref body,
                    }) => DefaultNotificationBuilder::new()
                        .title(title.as_str())
                        .body(body.as_str()),
                    None => DefaultNotificationBuilder::new()
                        .title("Konstruct")
                        .body("New message"),
                };
                let sound = payload.aps.sound.as_deref().unwrap_or("default");
                let mut builder = builder
                    .sound(sound)
                    .content_available() // wake app even for visible alerts (lock screen + killed)
                    .mutable_content(); // lets iOS notification extension process it in foreground
                if let Some(badge) = payload.aps.badge {
                    builder = builder.badge(badge);
                }
                builder.build(device_token, options)
            }
            PushType::Voip => DefaultNotificationBuilder::new().build(device_token, options),
        };

        // Attach our custom `construct` metadata so the iOS app knows message type / conversation
        if let Some(ref construct_data) = payload.construct
            && let Err(e) = built.add_custom_data("construct", construct_data)
        {
            warn!("Failed to attach custom APNs data: {}", e);
        }

        if let Some(ref call_data) = payload.construct_call
            && let Err(e) = built.add_custom_data("construct_call", call_data)
        {
            warn!("Failed to attach custom APNs call data: {}", e);
        }

        // Send notification
        match client.send(built).await {
            Ok(_response) => {
                debug!("APNs notification sent successfully");
                Ok(())
            }
            Err(e) => {
                // Detect permanently-invalid tokens so callers can disable them in the DB.
                // Per Apple, only an explicit reason condemns the DEVICE token:
                //   BadDeviceToken (400) → token malformed or wrong for this environment
                //   Unregistered   (410) → app was uninstalled, token no longer exists
                // 403 is a PROVIDER-auth verdict (Expired/Invalid/MissingProviderToken,
                // Forbidden, BadCertificate*) — the device token is fine; deleting it here
                // turns a server-side auth hiccup into silent push loss for every token
                // touched during the outage. Environment mismatch is no longer a 403 source
                // either: since 4e72ae7 sends are routed per-token to the matching endpoint.
                let is_invalid_token = if let ApnsH2Error::ResponseError(ref resp) = e {
                    if resp.code == 403 {
                        error!(
                            "APNs 403 (provider auth) — check .p8 key/key_id/team_id and \
                             server clock; reason: {:?} (empty body = APNs sent no reason). \
                             Device token NOT deleted.",
                            resp.error.as_ref().map(|body| &body.reason)
                        );
                    }
                    condemns_device_token(resp.code, resp.error.as_ref().map(|body| &body.reason))
                } else {
                    false
                };

                error!("Failed to send APNs notification: {:?}", e);
                warn!("APNs error: {}", e);

                if is_invalid_token {
                    return Err(ApnsSendError::InvalidToken);
                }
                Err(anyhow::anyhow!(e).into())
            }
        }
    }

    /// Send VoIP push notification (incoming call wake-up).
    ///
    /// Requires `APNS_VOIP_TOPIC` (or `APNS_VOIP_BUNDLE_ID`) to be set.
    pub async fn send_voip_incoming_call_push(
        &self,
        device_token: &str,
        call_id: String,
        caller_id: String,
        caller_name: String,
        call_type: String,
        offered_at: i64,
    ) -> Result<(), ApnsSendError> {
        if self.config.voip_topic.as_deref().unwrap_or("").is_empty() {
            // Explicitly skip — sending with the normal topic would be rejected by APNs.
            // Return an error (not Ok) so the caller does NOT count this as a delivered push:
            // previously this returned Ok(()), which made notification-service log
            // `sent_count=1` for a push that never left the server — masking the
            // misconfiguration and making incoming calls silently undeliverable offline.
            return Err(ApnsSendError::Other(anyhow::anyhow!(
                "APNS_VOIP_TOPIC not configured — VoIP push skipped"
            )));
        }

        let payload =
            ApnsPayload::voip_incoming_call(call_id, caller_id, caller_name, call_type, offered_at);
        self.send_notification(
            device_token,
            payload,
            PushType::Voip,
            NotificationPriority::High,
        )
        .await
    }
}

/// The topic a push is addressed to.
///
/// A VoIP push carries its own topic: sending it under the app's normal topic is rejected by
/// APNs, which is why `send_voip_incoming_call_push` refuses before reaching here when no VoIP
/// topic is configured. Everything else goes to the app topic.
///
/// Pure, so the choice is pinned by a table test instead of by a live send — the same reason
/// `condemns_device_token` is pure.
fn topic_for(config: &ApnsConfig, push_type: PushType) -> &str {
    match push_type {
        PushType::Voip => config.voip_topic.as_deref().unwrap_or(&config.topic),
        _ => &config.topic,
    }
}

/// `apns-collapse-id` of a message alert. A fixed string: each device token is one device, so a
/// constant already means "per device", and it carries nothing the push did not reveal. APNs
/// replaces a banner with a later one that has the same id, so a burst shows one banner, not ten.
pub const MESSAGE_COLLAPSE_ID: &str = "construct-message";

/// The `construct.type` a message push carries (see `blind_alert` in messaging-service).
const MESSAGE_ACTIVITY: &str = "new_message";

/// The collapse id for this push: only a message *alert*. Silent wakes, VoIP (a call must never
/// be merged into another) and contact-request alerts get none.
pub fn collapse_id_for(push_type: PushType, payload: &ApnsPayload) -> Option<&'static str> {
    let is_message = payload
        .construct
        .as_ref()
        .is_some_and(|c| c.notification_type == MESSAGE_ACTIVITY);
    (push_type == PushType::Visible && is_message).then_some(MESSAGE_COLLAPSE_ID)
}

/// The APNs request headers for a push. `apns-push-type` is REQUIRED since iOS 13 — missing it
/// causes silent drops.
fn notification_options<'a>(
    topic: &'a str,
    push_type: PushType,
    priority: NotificationPriority,
    payload: &ApnsPayload,
) -> NotificationOptions<'a> {
    NotificationOptions {
        apns_topic: Some(topic),
        apns_push_type: Some(match push_type {
            PushType::Silent => ApnsPushType::Background,
            PushType::Visible => ApnsPushType::Alert,
            PushType::Voip => ApnsPushType::Voip,
        }),
        apns_priority: Some(match push_type {
            PushType::Voip => Priority::High,
            _ => match priority {
                NotificationPriority::High => Priority::High,
                NotificationPriority::Low => Priority::Normal,
            },
        }),
        apns_expiration: match push_type {
            // Calls: do not store / retry when device is offline.
            PushType::Voip => Some(0),
            _ => None,
        },
        apns_collapse_id: collapse_id_for(push_type, payload)
            .and_then(|id| CollapseId::new(id).ok()),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ApsData, ConstructData};

    /// The token-deletion rule (`938f395`): only BadDeviceToken / Unregistered condemn a device
    /// token, and never on a 403 — not even if a 403 were to carry a device reason.
    #[test]
    fn only_an_explicit_device_reason_outside_403_condemns_the_token() {
        use ErrorReason as R;
        assert!(condemns_device_token(400, Some(&R::BadDeviceToken)));
        assert!(condemns_device_token(410, Some(&R::Unregistered)));

        for provider in [
            R::ExpiredProviderToken,
            R::InvalidProviderToken,
            R::MissingProviderToken,
            R::Forbidden,
            R::BadCertificate,
            R::BadCertificateEnvironment,
        ] {
            assert!(!condemns_device_token(403, Some(&provider)), "{provider:?}");
        }
        assert!(!condemns_device_token(403, None), "403 with no body");
        assert!(!condemns_device_token(403, Some(&R::BadDeviceToken)));
        assert!(!condemns_device_token(403, Some(&R::Unregistered)));

        // Other 4xx/5xx reasons describe the request or APNs, not the token.
        for (code, other) in [
            (400, R::BadTopic),
            (400, R::DeviceTokenNotForTopic),
            (400, R::PayloadEmpty),
            (429, R::TooManyRequests),
            (500, R::InternalServerError),
            (503, R::ServiceUnavailable),
        ] {
            assert!(
                !condemns_device_token(code, Some(&other)),
                "{code} {other:?}"
            );
        }
        assert!(!condemns_device_token(400, None), "no body, no verdict");
    }

    fn payload(activity: Option<&str>) -> ApnsPayload {
        ApnsPayload {
            aps: ApsData {
                content_available: Some(1),
                alert: None,
                sound: None,
                badge: None,
                mutable_content: None,
            },
            construct: activity.map(|a| ConstructData {
                notification_type: a.to_string(),
                conversation_id: None,
            }),
            construct_call: None,
        }
    }

    fn collapse(push_type: PushType, activity: Option<&str>) -> Option<String> {
        notification_options(
            "topic",
            push_type,
            NotificationPriority::High,
            &payload(activity),
        )
        .apns_collapse_id
        .map(|c| c.value.to_string())
    }

    #[test]
    fn a_message_alert_carries_the_fixed_collapse_id() {
        assert_eq!(
            collapse(PushType::Visible, Some("new_message")).as_deref(),
            Some(MESSAGE_COLLAPSE_ID)
        );
    }

    #[test]
    fn nothing_else_is_collapsed() {
        assert_eq!(collapse(PushType::Silent, Some("new_message")), None);
        assert_eq!(collapse(PushType::Voip, Some("new_message")), None);
        assert_eq!(
            collapse(PushType::Visible, Some("contact_request_received")),
            None
        );
        assert_eq!(collapse(PushType::Visible, None), None);
    }

    #[test]
    fn collapse_id_fits_apns_limit() {
        assert!(CollapseId::new(MESSAGE_COLLAPSE_ID).is_ok());
    }

    // ── Request headers ─────────────────────────────────────────────────────

    fn config(enabled: bool, voip_topic: Option<&str>) -> ApnsConfig {
        ApnsConfig {
            enabled,
            environment: ApnsEnvironment::Development,
            key_path: String::new(),
            key_id: String::new(),
            team_id: String::new(),
            bundle_id: String::new(),
            topic: "cc.konstruct.app".to_string(),
            voip_topic: voip_topic.map(str::to_string),
            device_token_encryption_key: "0".repeat(64),
        }
    }

    fn options(
        push_type: PushType,
        priority: NotificationPriority,
    ) -> NotificationOptions<'static> {
        notification_options("cc.konstruct.app", push_type, priority, &payload(None))
    }

    /// `apns-push-type` is required since iOS 13: without it APNs drops the push without
    /// telling anyone, so the mapping from our three kinds to Apple's is not cosmetic.
    #[test]
    fn every_push_type_names_its_apns_header() {
        assert_eq!(
            options(PushType::Silent, NotificationPriority::Low).apns_push_type,
            Some(ApnsPushType::Background)
        );
        assert_eq!(
            options(PushType::Visible, NotificationPriority::High).apns_push_type,
            Some(ApnsPushType::Alert)
        );
        assert_eq!(
            options(PushType::Voip, NotificationPriority::High).apns_push_type,
            Some(ApnsPushType::Voip)
        );
    }

    #[test]
    fn every_push_type_carries_the_topic_it_was_given() {
        for push_type in [PushType::Silent, PushType::Visible, PushType::Voip] {
            assert_eq!(
                options(push_type, NotificationPriority::High).apns_topic,
                Some("cc.konstruct.app"),
                "{push_type:?} must name a topic or APNs rejects the request"
            );
        }
    }

    /// A call is time-critical: it must go out immediately whatever the caller asked for,
    /// and it must not be stored for retry — a wake-up delivered minutes later is a call
    /// the user already missed.
    #[test]
    fn a_voip_push_is_high_priority_and_expires_immediately() {
        let voip = options(PushType::Voip, NotificationPriority::Low);
        // `Priority` is not `PartialEq`, so the rendered value is the comparison — which is
        // also exactly the `apns-priority` header APNs receives.
        assert_eq!(format!("{:?}", voip.apns_priority), "Some(High)");
        assert_eq!(voip.apns_expiration, Some(0));

        for push_type in [PushType::Silent, PushType::Visible] {
            assert_eq!(
                options(push_type, NotificationPriority::High).apns_expiration,
                None,
                "{push_type:?} may be stored by APNs"
            );
        }
    }

    /// A VoIP push must travel under the VoIP topic; under the app topic APNs rejects it. The
    /// fallback to the app topic only covers the case `send_voip_incoming_call_push` already
    /// refuses (no VoIP topic configured), so it is recorded here, not endorsed.
    #[test]
    fn a_voip_push_is_addressed_to_the_voip_topic() {
        let bridged = config(false, Some("cc.konstruct.app.voip"));
        assert_eq!(topic_for(&bridged, PushType::Voip), "cc.konstruct.app.voip");
        for push_type in [PushType::Silent, PushType::Visible] {
            assert_eq!(
                topic_for(&bridged, push_type),
                "cc.konstruct.app",
                "{push_type:?} must not be sent to the VoIP topic"
            );
        }
        assert_eq!(
            topic_for(&config(false, None), PushType::Voip),
            "cc.konstruct.app"
        );
    }

    #[test]
    fn a_message_priority_maps_to_the_apns_one() {
        assert_eq!(
            format!(
                "{:?}",
                options(PushType::Visible, NotificationPriority::High).apns_priority
            ),
            "Some(High)"
        );
        assert_eq!(
            format!(
                "{:?}",
                options(PushType::Visible, NotificationPriority::Low).apns_priority
            ),
            "Some(Normal)"
        );
    }

    // ── Initialization and the disabled path ─────────────────────────────────

    /// Disabled is the documented way to run without APNs credentials, and it must stay a
    /// no-op: otherwise an empty `APNS_KEY_PATH` decides whether the service starts.
    #[tokio::test]
    async fn initialize_is_a_no_op_when_disabled() {
        ApnsClient::new(config(false, None))
            .expect("client")
            .initialize()
            .await
            .expect("a disabled client must not need a key file");
    }

    /// Enabled means the key is expected. Reporting success without it would move the
    /// failure to the first push, where it is a silently dropped notification.
    #[tokio::test]
    async fn initialize_refuses_when_enabled_without_a_readable_key() {
        let mut cfg = config(true, None);
        cfg.key_path = "/nonexistent/construct-test/AuthKey.p8".to_string();
        let err = ApnsClient::new(cfg)
            .expect("client")
            .initialize()
            .await
            .expect_err("an enabled client without a key must refuse to start");
        assert!(
            err.to_string().contains("Failed to open APNs key file"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn send_is_a_no_op_when_disabled_and_an_error_before_initialize() {
        let payload = payload(None);

        ApnsClient::new(config(false, None))
            .expect("client")
            .send_notification(
                "token",
                payload.clone(),
                PushType::Silent,
                NotificationPriority::Low,
            )
            .await
            .expect("a disabled client must not attempt a send");

        let err = ApnsClient::new(config(true, None))
            .expect("client")
            .send_notification(
                "token",
                payload,
                PushType::Silent,
                NotificationPriority::Low,
            )
            .await
            .expect_err("an initialized-only client must refuse");
        assert!(
            err.to_string().contains("APNs client not initialized"),
            "unexpected error: {err}"
        );
    }

    /// The VoIP topic is what makes an incoming call wake a backgrounded device. Sending
    /// without it, under the normal topic, is rejected by APNs — so returning `Ok(())`
    /// reported a delivery that never happened and made the misconfiguration invisible.
    #[tokio::test]
    async fn a_voip_push_without_a_topic_is_an_error_not_a_silent_success() {
        let err = ApnsClient::new(config(false, None))
            .expect("client")
            .send_voip_incoming_call_push(
                "token",
                "call-1".to_string(),
                "user-1".to_string(),
                "Caller".to_string(),
                "audio".to_string(),
                1_700_000_000,
            )
            .await
            .expect_err("a VoIP push without a topic must not report success");
        assert!(
            err.to_string().contains("APNS_VOIP_TOPIC not configured"),
            "unexpected error: {err}"
        );
    }
}
