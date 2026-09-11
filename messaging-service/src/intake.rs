//! Intake credentials — what a sealed envelope carries instead of a Privacy Pass token.
//!
//! Measured on two devices 2026-09-11, in one ordinary conversation, delivery receipts alone were
//! 36–38% of all token spend — and they are spent by the person who was *written to*. A token per
//! sealed envelope charges the same for a stranger's first contact and for the four-hundredth
//! message between two people who have been talking for a year.
//!
//! This server cannot be told which envelopes to exempt: `content_type` lives inside the seal on
//! purpose, so waiving a token for a receipt would put message kind back on the outer envelope.
//! So an envelope that owes nothing says so by carrying a credential the *recipient* issued:
//!
//! ```text
//! intake_tag = HMAC-SHA256(intake_key,
//!                          "knst-intake-v1" ‖ 0x00 ‖ recipient_account_id ‖ 0x00 ‖ epoch_be64)
//!              [0..16]
//! ```
//!
//! derived in `construct-core::intake` and nowhere else. **This service never computes a tag.** It
//! stores what the recipient published and compares. That is deliberate: holding `intake_key`
//! would make a database dump free sending to every account, where holding only tags limits a dump
//! to the epochs it happens to contain.
//!
//! Design: `construct-docs/decisions/contact-traffic-is-vouched-not-purchased.md`.

use construct_crypto::privacy_pass::open_sealed_token_bytes;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Length of a tag, matching `construct-core::intake::INTAKE_TAG_LEN`.
pub(crate) const INTAKE_TAG_LEN: usize = 16;

/// Seconds per epoch — one UTC day. Must match `construct-core::intake::INTAKE_EPOCH_SECONDS`.
pub(crate) const INTAKE_EPOCH_SECONDS: u64 = 86_400;

/// How long a published tag is kept past the end of its own epoch.
///
/// The previous epoch stays acceptable so a send that crosses midnight — or a client whose clock
/// is a few minutes behind — is not charged for the calendar. One extra epoch, not more: every
/// epoch kept alive is an epoch a leaked tag remains usable in.
pub(crate) const INTAKE_TAG_GRACE_EPOCHS: u64 = 1;

/// Most epochs one `PublishIntakeTags` call may carry.
///
/// A recipient publishes ahead so a device that has been offline for a day does not break its own
/// incoming traffic. Two weeks is generous for that and still bounds what one call can write.
pub(crate) const MAX_PUBLISHED_EPOCHS: usize = 14;

/// What the credential on an envelope amounts to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IntakeCheck {
    /// A valid credential for this recipient and a live epoch. No token is owed.
    Vouched,
    /// No credential on the envelope. The token path applies, exactly as before.
    Absent,
    /// A credential that did not open, was the wrong size, or matched nothing — including when
    /// Redis could not answer.
    ///
    /// Deliberately indistinguishable from `Absent` in consequence: the envelope falls back to the
    /// token path and delivery is unaffected. A wrong tag must never be a delivery failure on its
    /// own, or a clock an hour behind would drop messages rather than charge for them.
    Unrecognised,
}

impl IntakeCheck {
    pub(crate) fn as_label(self) -> &'static str {
        match self {
            Self::Vouched => "vouched",
            Self::Absent => "absent",
            Self::Unrecognised => "unrecognised",
        }
    }

    /// Does this envelope still owe a Privacy Pass token?
    pub(crate) fn owes_token(self) -> bool {
        self != Self::Vouched
    }
}

/// The epoch containing `unix_seconds`.
pub(crate) fn intake_epoch(unix_seconds: u64) -> u64 {
    unix_seconds / INTAKE_EPOCH_SECONDS
}

/// Redis key for one account's tag in one epoch.
///
/// The account id is hashed rather than embedded. A Redis keyspace scan would otherwise enumerate
/// every account that has published, which is a user list this service has no reason to hand out —
/// the same reasoning that has `pp:unit:` hash its inputs instead of concatenating them.
pub(crate) fn tag_key(recipient_user_id: &str, epoch: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(recipient_user_id.trim().to_ascii_lowercase().as_bytes());
    hasher.update(b"|");
    hasher.update(epoch.to_be_bytes());
    format!("intake:{}", hex::encode(hasher.finalize()))
}

/// Seconds a tag published for `epoch` should live, given `now_epoch`.
///
/// Returns `None` for an epoch already past its grace — nothing to store, and a caller that stored
/// it anyway would be writing a key that can never be read.
pub(crate) fn tag_ttl_seconds(epoch: u64, now_epoch: u64) -> Option<u64> {
    let last_live_epoch = epoch + INTAKE_TAG_GRACE_EPOCHS;
    if last_live_epoch < now_epoch {
        return None;
    }
    // Live until the end of the last epoch that still accepts it, counted from the start of now.
    Some((last_live_epoch + 1 - now_epoch) * INTAKE_EPOCH_SECONDS)
}

/// Which epochs an envelope arriving in `now_epoch` may present a tag for.
pub(crate) fn acceptable_epochs(now_epoch: u64) -> Vec<u64> {
    let mut epochs = vec![now_epoch];
    for back in 1..=INTAKE_TAG_GRACE_EPOCHS {
        if let Some(e) = now_epoch.checked_sub(back) {
            epochs.push(e);
        }
    }
    epochs
}

/// Does `presented` match `stored`?
///
/// Constant time, and not as decoration. The server answers accept/reject on a 16-byte secret; a
/// comparison that returns early on the first differing byte turns a 2^-128 forgery into roughly
/// 16 × 256 measured requests.
pub(crate) fn tag_matches(presented: &[u8], stored: &[u8]) -> bool {
    // `subtle` already returns false for slices of different lengths, so this is not the guard
    // against a 32-byte token presented here. What it does catch is the case `subtle` cannot: two
    // values that are equal to each other and both the wrong size — a truncated or corrupted entry
    // in Redis, matchable by presenting the same truncation. `store_published_tag` refuses to write
    // one, and "cannot be written" is not a property a credential check should lean on.
    if presented.len() != INTAKE_TAG_LEN || stored.len() != INTAKE_TAG_LEN {
        return false;
    }
    presented.ct_eq(stored).into()
}

/// Does this envelope carry a credential the recipient issued?
///
/// Reuses `open_sealed_token_bytes` — the same X25519 seal `token_bytes` uses, with the same HKDF
/// info. A second seal primitive differing only in a constant would be a second carrier of one
/// meaning, and the client would then hold two ways to seal sixteen bytes. Moving a blob between
/// the two fields fails closed in both directions anyway: a 32-byte token presented here is the
/// wrong length for a tag, and a 16-byte tag presented as a token fails the `[u8; 32]` conversion.
///
/// Every failure returns `Unrecognised`, including a Redis outage. That is the conservative
/// direction: an envelope that cannot be shown to be vouched falls back to paying, which is what
/// it did before this existed. The opposite default — trusting a credential we could not check —
/// would turn one unreachable Redis into free sending to everybody.
pub(crate) async fn check_intake_credential(
    conn: &mut redis::aio::ConnectionManager,
    server_secret: Option<&x25519_dalek::StaticSecret>,
    intake_tag_sealed: &[u8],
    recipient_user_id: &str,
    now_unix: u64,
) -> IntakeCheck {
    if intake_tag_sealed.is_empty() {
        return IntakeCheck::Absent;
    }
    let Some(secret) = server_secret else {
        // No key to open it with — the same state in which tokens cannot be redeemed either.
        return IntakeCheck::Unrecognised;
    };
    let Ok(presented) = open_sealed_token_bytes(intake_tag_sealed, secret) else {
        return IntakeCheck::Unrecognised;
    };
    if presented.len() != INTAKE_TAG_LEN {
        return IntakeCheck::Unrecognised;
    }

    for epoch in acceptable_epochs(intake_epoch(now_unix)) {
        let key = tag_key(recipient_user_id, epoch);
        let stored: redis::RedisResult<Option<Vec<u8>>> =
            redis::cmd("GET").arg(&key).query_async(conn).await;
        match stored {
            Ok(Some(bytes)) if tag_matches(&presented, &bytes) => return IntakeCheck::Vouched,
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(error = %e, "intake tag lookup unavailable — falling back to the token path");
                return IntakeCheck::Unrecognised;
            }
        }
    }
    IntakeCheck::Unrecognised
}

/// Store one published tag, or say why it was not stored.
///
/// The recipient owns its own tags and nothing else: the caller must pass the *authenticated*
/// account id, never one taken from a request body, or publishing would be a way to vouch for
/// traffic to someone else.
pub(crate) async fn store_published_tag(
    conn: &mut redis::aio::ConnectionManager,
    recipient_user_id: &str,
    epoch: u64,
    tag: &[u8],
    now_unix: u64,
) -> Result<bool, redis::RedisError> {
    if tag.len() != INTAKE_TAG_LEN {
        return Ok(false);
    }
    let Some(ttl) = tag_ttl_seconds(epoch, intake_epoch(now_unix)) else {
        return Ok(false);
    };
    let key = tag_key(recipient_user_id, epoch);
    redis::cmd("SET")
        .arg(&key)
        .arg(tag)
        .arg("EX")
        .arg(ttl)
        .query_async::<()>(conn)
        .await?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_epoch_is_a_utc_day() {
        assert_eq!(intake_epoch(0), 0);
        assert_eq!(intake_epoch(INTAKE_EPOCH_SECONDS - 1), 0);
        assert_eq!(intake_epoch(INTAKE_EPOCH_SECONDS), 1);
        // 2026-09-11T00:00:00Z — the same vector construct-core pins.
        assert_eq!(intake_epoch(1_789_084_800), 20_707);
    }

    #[test]
    fn the_key_is_bound_to_both_account_and_epoch() {
        let a = "ffeeddc6-14f2-4d02-a66a-caf0d8dfeda8";
        let b = "9a921fe2-2f50-44cf-ba68-ed10422de0bc";
        assert_ne!(tag_key(a, 20_707), tag_key(b, 20_707));
        assert_ne!(tag_key(a, 20_707), tag_key(a, 20_708));
    }

    #[test]
    fn the_key_normalises_the_account_like_the_derivation_does() {
        // construct-core lowercases and trims before hashing. If this side did not, a client that
        // published with one spelling and sent with another would look unvouched and be charged,
        // with nothing anywhere reporting a mismatch — the 2026-07-22 recovery bug's shape.
        let a = "FFEEDDC6-14F2-4D02-A66A-CAF0D8DFEDA8";
        let b = "  ffeeddc6-14f2-4d02-a66a-caf0d8dfeda8 ";
        assert_eq!(tag_key(a, 20_707), tag_key(b, 20_707));
    }

    #[test]
    fn a_uuid_and_a_wire_string_land_on_the_same_key() {
        // The publisher's account arrives as a `Uuid` (from the auth token) and the sender's as a
        // wire `String` (SealedInner.recipient_user_id). They must meet at one key, or the
        // keyspace splits into one half nobody reads and one half nobody writes — and the only
        // symptom is that every contact keeps paying tokens.
        let id = uuid::Uuid::parse_str("ffeeddc6-14f2-4d02-a66a-caf0d8dfeda8").unwrap();
        assert_eq!(
            tag_key(&id.to_string(), 20_707),
            tag_key("FFEEDDC6-14F2-4D02-A66A-CAF0D8DFEDA8", 20_707),
            "Uuid::to_string stopped being the canonical spelling tag_key normalises to"
        );
    }

    #[test]
    fn the_key_does_not_leak_the_account_id() {
        // A keyspace scan must not enumerate who has published.
        let a = "ffeeddc6-14f2-4d02-a66a-caf0d8dfeda8";
        assert!(!tag_key(a, 20_707).contains("ffeeddc6"));
    }

    #[test]
    fn the_previous_epoch_is_still_acceptable_but_the_one_before_is_not() {
        let e = acceptable_epochs(20_707);
        assert!(e.contains(&20_707), "the current epoch must be accepted");
        assert!(
            e.contains(&20_706),
            "a send crossing midnight must not be charged for the calendar"
        );
        assert!(
            !e.contains(&20_705),
            "every extra epoch is an epoch a leaked tag still works in"
        );
    }

    #[test]
    fn epoch_zero_does_not_underflow() {
        // `checked_sub` and not `- 1`: a test clock at the Unix epoch is not a reason to panic.
        assert_eq!(acceptable_epochs(0), vec![0]);
    }

    #[test]
    fn a_tag_for_a_future_epoch_lives_past_it() {
        // Published a week ahead, it must still be there a week later.
        let ttl = tag_ttl_seconds(20_714, 20_707).expect("future epoch is storable");
        assert!(
            ttl > 7 * INTAKE_EPOCH_SECONDS,
            "a tag published ahead expired before its epoch"
        );
    }

    #[test]
    fn a_tag_for_the_current_epoch_outlives_its_grace() {
        let ttl = tag_ttl_seconds(20_707, 20_707).expect("current epoch is storable");
        assert_eq!(ttl, 2 * INTAKE_EPOCH_SECONDS);
    }

    #[test]
    fn a_tag_past_its_grace_is_not_stored_at_all() {
        // 20_705 stopped being acceptable when now_epoch reached 20_707, so writing it would
        // create a key nothing can ever read.
        assert_eq!(tag_ttl_seconds(20_705, 20_707), None);
        // The boundary case is the one worth pinning: the previous epoch IS still storable.
        assert!(tag_ttl_seconds(20_706, 20_707).is_some());
    }

    #[test]
    fn a_matching_tag_matches() {
        let t = [9u8; INTAKE_TAG_LEN];
        assert!(tag_matches(&t, &t));
    }

    #[test]
    fn one_flipped_bit_does_not_match() {
        let a = [9u8; INTAKE_TAG_LEN];
        let mut b = a;
        b[INTAKE_TAG_LEN - 1] ^= 1;
        assert!(!tag_matches(&a, &b));
    }

    #[test]
    fn a_wrong_length_never_matches_even_as_a_prefix() {
        // A 32-byte Privacy Pass token moved into the intake field decrypts fine and must not be
        // accepted because its first 16 bytes happen to line up with something.
        let t = [9u8; INTAKE_TAG_LEN];
        assert!(!tag_matches(&[9u8; 32], &t));
        assert!(!tag_matches(&t, &[9u8; 32]));
        assert!(!tag_matches(&[], &t));
        assert!(!tag_matches(&t, &[]));
    }

    #[test]
    fn two_equal_but_wrong_length_values_do_not_match() {
        // The case the length guard exists for, and the only one — `subtle` handles mismatched
        // lengths on its own. A short value in Redis must not be openable by presenting the same
        // short value. Verified by mutation 2026-09-11: without the guard this is the one test
        // that goes red, and the wrong-length-prefix test below stays green on its own.
        let short = [9u8; 8];
        assert!(!tag_matches(&short, &short));
        let long = [9u8; 32];
        assert!(!tag_matches(&long, &long));
    }

    #[test]
    fn an_unrecognised_credential_still_owes_a_token() {
        // The three outcomes collapse to one question at the call site, and only "vouched" is free.
        assert!(!IntakeCheck::Vouched.owes_token());
        assert!(IntakeCheck::Absent.owes_token());
        assert!(IntakeCheck::Unrecognised.owes_token());
    }
}
