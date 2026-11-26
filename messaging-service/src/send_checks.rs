//! Checks every send path runs before it dispatches, on unary `SendMessage` and on the
//! `MessageStream` send frame alike. A leaf module: both transports import it, it imports
//! neither.

use tonic::Status;

/// Validates that `payload` is non-empty and within the 64 KiB size limit.
pub(crate) fn validate_payload(payload: &[u8]) -> Result<(), String> {
    if payload.is_empty() {
        return Err("encrypted_payload is required".to_string());
    }
    const MAX_PAYLOAD_BYTES: usize = 64 * 1024;
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(format!(
            "encrypted_payload exceeds maximum size ({} > {} bytes)",
            payload.len(),
            MAX_PAYLOAD_BYTES
        ));
    }
    Ok(())
}

/// The device a regular send is charged to: always the one the access token names.
///
/// `envelope.sender_device` is client-asserted. Until 2026-10-29 Sentinel keyed on it and ran only
/// when it was non-empty, on both transports: a banned device skipped the ban, server-side blocks and
/// every per-device quota by leaving it out, and a device naming a sibling spent the sibling's quota
/// (construct-docs todo 228). The envelope may still carry it — clients do — but it must agree.
///
/// A token with no device is refused rather than waved through: every token issued since 2026-04
/// names one, refresh tokens live 90 days and 0.20.0 rejects everything older, so the only way to
/// arrive here without one is a token this server did not mean to issue.
pub(crate) fn sentinel_sender_device<'a>(
    token_device: Option<&'a str>,
    envelope_device: Option<&str>,
) -> Result<&'a str, Status> {
    let token_device = token_device
        .filter(|d| !d.is_empty())
        .ok_or_else(|| Status::unauthenticated("access token is not bound to a device"))?;
    match envelope_device.filter(|d| !d.is_empty()) {
        Some(claimed) if !claimed.eq_ignore_ascii_case(token_device) => Err(
            Status::permission_denied("sender_device does not match authenticated device"),
        ),
        _ => Ok(token_device),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payload_size_empty_rejected() {
        assert!(validate_payload(&[]).is_err());
    }

    #[test]
    fn test_payload_size_64kb_accepted() {
        let payload = vec![0u8; 65535];
        assert!(validate_payload(&payload).is_ok());
    }

    #[test]
    fn test_payload_size_over_64kb_rejected() {
        let payload = vec![0u8; 65537];
        assert!(validate_payload(&payload).is_err());
    }

    // ── sentinel_sender_device: Sentinel is charged to the token's device ──

    const TOKEN_DEVICE: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn sentinel_charges_the_token_device_when_the_envelope_names_none() {
        // The bypass: an envelope without sender_device used to skip Sentinel entirely.
        assert_eq!(
            sentinel_sender_device(Some(TOKEN_DEVICE), None).unwrap(),
            TOKEN_DEVICE
        );
        assert_eq!(
            sentinel_sender_device(Some(TOKEN_DEVICE), Some("")).unwrap(),
            TOKEN_DEVICE
        );
    }

    #[test]
    fn sentinel_refuses_an_envelope_naming_another_device() {
        // A sibling's or a made-up id would otherwise be charged instead of the sender.
        let err =
            sentinel_sender_device(Some(TOKEN_DEVICE), Some("ffffffffffffffffffffffffffffffff"))
                .expect_err("a different device must be refused");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn sentinel_accepts_the_envelope_naming_the_token_device_in_any_case() {
        assert_eq!(
            sentinel_sender_device(Some(TOKEN_DEVICE), Some(&TOKEN_DEVICE.to_uppercase())).unwrap(),
            TOKEN_DEVICE
        );
    }

    #[test]
    fn sentinel_refuses_a_token_without_a_device() {
        for token_device in [None, Some("")] {
            let err = sentinel_sender_device(token_device, Some(TOKEN_DEVICE))
                .expect_err("no device in the token must not fall back to the envelope");
            assert_eq!(err.code(), tonic::Code::Unauthenticated);
        }
    }
}
