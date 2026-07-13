// ============================================================================
// Secret hygiene — boot-time fail-fast validation of critical secrets
// ============================================================================
//
// Runs once from `Config::from_env()` for EVERY service. The goal is to turn a
// silent misconfiguration into a loud boot failure, because the alternative is a
// service that starts "successfully" and then quietly corrupts or drops traffic.
//
// Design rules (deliberately conservative to avoid breaking healthy deploys):
//   * A secret that is ABSENT/empty is NOT an error here — that is a legitimate
//     "feature disabled" state handled per-service (e.g. TOKEN_ISSUER_KEY unset ⇒
//     IssueTokens disabled). Requiring specific secrets per service is the service's
//     job, not this crate's.
//   * A secret that is PRESENT but MALFORMED is a hard error — wrong length, wrong
//     encoding, or surrounding quotes. A healthy production value always passes.
//
// This catches the exact misconfig class seen on 2026-07-13:
//   - `SERVER_SIGNING_KEY` blanked by an empty `${VAR}` compose interpolation
//     (federation.rs only validated it when FEDERATION_ENABLED=true, but it is ALSO
//     the token-encryption seed — so with federation off the bad value slipped through).
//   - `KEY="value"` with literal quotes (env_file passes quotes verbatim).
//   - hex used where base64/32-bytes is required (64 hex → 48 bytes, not 32).
//
// See construct-docs decisions/key-rotation-and-secret-hygiene.md and
// deployment/stealth-token-keys-runbook.md §6.

use anyhow::{bail, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

/// Env var names whose PRESENT value must never carry surrounding quotes/whitespace.
/// (env_file passes quotes literally, so `KEY="abc"` becomes the 5-char string `"abc"`.)
const QUOTE_SENSITIVE: &[&str] = &[
    "SERVER_SIGNING_KEY",
    "TOKEN_ISSUER_KEY",
    "BUNDLE_SIGNING_KEY",
    "BUNDLE_SIGNING_PUBLIC_KEY",
    "APNS_DEVICE_TOKEN_ENCRYPTION_KEY",
    "USERNAME_HMAC_SECRET",
    "CONTACT_HMAC_SECRET",
    "MEDIA_HMAC_SECRET",
    "CSRF_SECRET",
    "DELIVERY_SECRET_KEY",
    "LOG_HASH_SALT",
    "TURN_SECRET",
];

/// Read an env var, returning `None` for absent OR empty (both = "not configured").
fn present(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

/// Fail if a present value is wrapped in literal quotes — the classic env_file mistake.
fn reject_quotes(name: &str, value: &str) -> Result<()> {
    let t = value.trim();
    let quoted = (t.starts_with('"') && t.ends_with('"') && t.len() >= 2)
        || (t.starts_with('\'') && t.ends_with('\'') && t.len() >= 2);
    if quoted {
        bail!(
            "{name} has surrounding quotes — remove them. env_file passes quotes \
             literally, so the value is used verbatim (including the quote chars). \
             Write `{name}=value`, not `{name}=\"value\"`."
        );
    }
    Ok(())
}

/// A present value must base64-decode to exactly `bytes` bytes.
fn require_base64_len(name: &str, value: &str, bytes: usize) -> Result<()> {
    match BASE64.decode(value.trim()) {
        Ok(b) if b.len() == bytes => Ok(()),
        Ok(b) => bail!(
            "{name} must decode to exactly {bytes} bytes (got {}). If you used \
             `openssl rand -hex {bytes}`, that is the wrong encoding — this key is \
             base64: use `openssl rand -base64 {bytes}`.",
            b.len()
        ),
        Err(e) => bail!("{name} is not valid base64: {e}"),
    }
}

/// A present value must be exactly `bytes*2` lowercase/uppercase hex chars.
fn require_hex_len(name: &str, value: &str, bytes: usize) -> Result<()> {
    let t = value.trim();
    let want = bytes * 2;
    if t.len() != want || hex::decode(t).is_err() {
        bail!(
            "{name} must be exactly {want} hex chars ({bytes} bytes) — \
             generate with `openssl rand -hex {bytes}`."
        );
    }
    Ok(())
}

/// Boot-time fail-fast on malformed secrets. Called from `Config::from_env()`.
///
/// Errors only on PRESENT-but-malformed values; absent/empty is left to per-service
/// "feature disabled" handling. A healthy production configuration always passes.
pub fn validate() -> Result<()> {
    // 1. No secret may carry literal surrounding quotes.
    for name in QUOTE_SENSITIVE {
        if let Some(v) = present(name) {
            reject_quotes(name, &v)?;
        }
    }

    // 2. Format/length invariants for the keyed secrets. Checked regardless of any
    //    FEDERATION_ENABLED / policy flag — e.g. SERVER_SIGNING_KEY is validated even
    //    with federation off, because it is also the token-encryption seed.
    if let Some(v) = present("SERVER_SIGNING_KEY") {
        require_base64_len("SERVER_SIGNING_KEY", &v, 32)?;
    }
    if let Some(v) = present("BUNDLE_SIGNING_KEY") {
        require_base64_len("BUNDLE_SIGNING_KEY", &v, 32)?;
    }
    if let Some(v) = present("BUNDLE_SIGNING_PUBLIC_KEY") {
        require_base64_len("BUNDLE_SIGNING_PUBLIC_KEY", &v, 32)?;
    }
    if let Some(v) = present("TOKEN_ISSUER_KEY") {
        require_hex_len("TOKEN_ISSUER_KEY", &v, 32)?;
    }
    if let Some(v) = present("APNS_DEVICE_TOKEN_ENCRYPTION_KEY") {
        require_hex_len("APNS_DEVICE_TOKEN_ENCRYPTION_KEY", &v, 32)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_len_accepts_32_rejects_others() {
        let ok = BASE64.encode([0u8; 32]);
        assert!(require_base64_len("K", &ok, 32).is_ok());
        // 64 hex chars fed as base64 decodes to 48 bytes — the hex/base64 mix-up.
        let hex64 = "ff".repeat(32);
        assert!(require_base64_len("K", &hex64, 32).is_err());
        assert!(require_base64_len("K", "not base64!!", 32).is_err());
    }

    #[test]
    fn hex_len_accepts_64_rejects_others() {
        assert!(require_hex_len("K", &"a".repeat(64), 32).is_ok());
        assert!(require_hex_len("K", &"a".repeat(63), 32).is_err());
        assert!(require_hex_len("K", &"zz".repeat(32), 32).is_err()); // non-hex
        let b64 = BASE64.encode([0u8; 32]); // base64 where hex expected
        assert!(require_hex_len("K", &b64, 32).is_err());
    }

    #[test]
    fn rejects_surrounding_quotes() {
        assert!(reject_quotes("K", "\"abc\"").is_err());
        assert!(reject_quotes("K", "'abc'").is_err());
        assert!(reject_quotes("K", "abc").is_ok());
    }
}
