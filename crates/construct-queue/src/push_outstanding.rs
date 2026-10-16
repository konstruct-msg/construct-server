// "A message push is outstanding for this device" marker.
//
// The server sends an alert push per envelope, and the notification extension cannot suppress
// any of them, so a burst of envelopes is a burst of banners. One banner per unread batch is
// enough: while the previous push has not been consumed, further envelopes for the device do
// not push again.

/// How long a "push outstanding" marker lives if the device never reads its mailbox.
///
/// This bounds the cost of a lost push. iOS may drop an alert (device offline past APNs'
/// retention, Focus, the app swiped away mid-delivery), and the marker would then silence the
/// device until it next fetches — which, for a device that never saw a banner, may be never.
/// Ten minutes is long enough to absorb a conversation's burst and short enough that a dropped
/// push costs one delayed banner, not a muted device. Do not raise it without raising that
/// trade-off on purpose.
pub const PUSH_OUTSTANDING_TTL_SECONDS: u64 = 600;

/// Redis key of the marker. Keyed by the raw device id, like `revoked_device:{device_id}`:
/// the id is already what every device-scoped key in this store is named by.
pub fn push_outstanding_key(device_id: &str) -> String {
    format!("push:outstanding:{device_id}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_is_per_device() {
        assert_eq!(push_outstanding_key("abc"), "push:outstanding:abc");
        assert_ne!(push_outstanding_key("abc"), push_outstanding_key("abd"));
    }

    #[test]
    fn ttl_is_bounded_so_a_lost_push_cannot_silence_a_device() {
        assert_eq!(PUSH_OUTSTANDING_TTL_SECONDS, 600);
    }
}
