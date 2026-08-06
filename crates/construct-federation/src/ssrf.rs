// ============================================================================
// Federation SSRF guards
// ============================================================================
//
// PublicKeyCache and discovery fetch `https://{domain}/.well-known/konstruct`.
// The domain comes from S2S request fields (`origin_server`) or outbound
// routing — an attacker who can hit `/federation/v1/*` (or force a server to
// dial a peer) must not turn that into a probe of internal IPs (cloud
// metadata, Redis, localhost).
//
// Defenses:
// 1. Hostname syntax only (no schemes, paths, userinfo, raw IPs).
// 2. Blocked special-use names (localhost, .local, .internal, …).
// 3. DNS resolve and reject private / loopback / link-local / CGNAT / ULA.
// 4. Callers should also disable HTTP redirects on the fetch client.
//
// ============================================================================

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};

/// Validate that `domain` is a bare public hostname safe to use in a
/// well-known fetch URL. Does **not** perform DNS — call
/// [`assert_hostname_resolves_public`] before connecting.
pub fn validate_federation_hostname(domain: &str) -> Result<(), String> {
    let raw = domain.trim();
    if raw.is_empty() || raw.len() > 253 {
        return Err("domain empty or too long".into());
    }

    // Reject anything that is not a bare host[:port].
    let lower = raw.to_ascii_lowercase();
    if lower.contains("://")
        || lower.contains('/')
        || lower.contains('\\')
        || lower.contains('@')
        || lower.contains('?')
        || lower.contains('#')
        || lower.contains(' ')
        || lower.contains('\t')
        || lower.contains('%')
    {
        return Err("domain must be a bare hostname (optional :port)".into());
    }

    // Split optional :port (IPv6 literals already rejected later).
    let (host, port_opt) = if let Some((h, p)) = lower.rsplit_once(':') {
        // "example.com:8443" — port must be numeric; host must not be empty.
        if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() && p.len() <= 5 {
            let port: u16 = p
                .parse()
                .map_err(|_| "invalid port in domain".to_string())?;
            if port == 0 {
                return Err("invalid port in domain".into());
            }
            (h, Some(port))
        } else {
            // Not a port suffix (e.g. accidental garbage) — treat whole string as host.
            (lower.as_str(), None)
        }
    } else {
        (lower.as_str(), None)
    };
    let _ = port_opt; // reserved for resolve; host validation below

    let host = host.trim_end_matches('.');
    if host.is_empty() {
        return Err("empty host".into());
    }

    // Reject IP literals (v4 and bare v6).
    if host.parse::<IpAddr>().is_ok() || host.starts_with('[') {
        return Err("IP literals are not allowed as federation domains".into());
    }

    // DNS label rules (RFC 1035 + LDH).
    for label in host.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err("invalid DNS label length".into());
        }
        if !label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            return Err("invalid characters in domain".into());
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("DNS label cannot start/end with hyphen".into());
        }
    }

    // Special-use / internal names.
    if host == "localhost"
        || host.ends_with(".localhost")
        || host.ends_with(".local")
        || host.ends_with(".internal")
        || host.ends_with(".intranet")
        || host.ends_with(".lan")
        || host.ends_with(".home")
        || host.ends_with(".corp")
        || host == "metadata.google.internal"
        || host.ends_with(".metadata.google.internal")
    {
        return Err("blocked special-use or internal domain".into());
    }

    Ok(())
}

/// Resolve `domain` and ensure every resulting address is publicly routable.
pub fn assert_hostname_resolves_public(domain: &str) -> Result<(), String> {
    validate_federation_hostname(domain)?;

    let lower = domain.trim().to_ascii_lowercase();
    let (host, port) = split_host_port(&lower);
    let host = host.trim_end_matches('.');

    let addrs = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("DNS resolution failed: {e}"))?;

    let mut saw_any = false;
    for addr in addrs {
        saw_any = true;
        if !is_public_ip(addr.ip()) {
            return Err(format!(
                "domain resolves to non-public address {} (SSRF blocked)",
                addr.ip()
            ));
        }
    }
    if !saw_any {
        return Err("DNS resolution returned no addresses".into());
    }
    Ok(())
}

fn split_host_port(domain: &str) -> (&str, u16) {
    if let Some((h, p)) = domain.rsplit_once(':')
        && !h.is_empty()
        && p.chars().all(|c| c.is_ascii_digit())
        && let Ok(port) = p.parse::<u16>()
        && port != 0
    {
        return (h, port);
    }
    (domain, 443)
}

/// True if the IP is safe to dial from a multi-tenant server (not private/loopback/etc.).
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => is_public_v6(v6),
    }
}

fn is_public_v4(v4: Ipv4Addr) -> bool {
    if v4.is_private()
        || v4.is_loopback()
        || v4.is_link_local()
        || v4.is_broadcast()
        || v4.is_documentation()
        || v4.is_unspecified()
        || v4.is_multicast()
    {
        return false;
    }
    // CGNAT 100.64.0.0/10
    let o = v4.octets();
    if o[0] == 100 && (o[1] & 0xc0) == 64 {
        return false;
    }
    // Benchmarking 198.18.0.0/15
    if o[0] == 198 && (o[1] == 18 || o[1] == 19) {
        return false;
    }
    // IETF protocol assignments 192.0.0.0/24 (except continuum)
    if o[0] == 192 && o[1] == 0 && o[2] == 0 {
        return false;
    }
    true
}

fn is_public_v6(v6: Ipv6Addr) -> bool {
    if v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() {
        return false;
    }
    // Link-local fe80::/10
    let s = v6.segments();
    if (s[0] & 0xffc0) == 0xfe80 {
        return false;
    }
    // Unique local fc00::/7
    if (s[0] & 0xfe00) == 0xfc00 {
        return false;
    }
    // IPv4-mapped — recurse on embedded v4
    if let Some(v4) = v6.to_ipv4_mapped() {
        return is_public_v4(v4);
    }
    // Discard prefix 100::/64
    if s[0] == 0x0100 && s[1] == 0 && s[2] == 0 && s[3] == 0 {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_normal_public_hostnames() {
        assert!(validate_federation_hostname("peer.konstruct.cc").is_ok());
        assert!(validate_federation_hostname("Example.COM").is_ok());
        assert!(validate_federation_hostname("a.b.example.org:8443").is_ok());
    }

    #[test]
    fn rejects_urls_paths_and_userinfo() {
        assert!(validate_federation_hostname("https://evil.com").is_err());
        assert!(validate_federation_hostname("evil.com/path").is_err());
        assert!(validate_federation_hostname("user@evil.com").is_err());
        assert!(validate_federation_hostname("evil.com?q=1").is_err());
    }

    #[test]
    fn rejects_ip_literals() {
        assert!(validate_federation_hostname("127.0.0.1").is_err());
        assert!(validate_federation_hostname("10.0.0.5").is_err());
        assert!(validate_federation_hostname("169.254.169.254").is_err());
        assert!(validate_federation_hostname("[::1]").is_err());
    }

    #[test]
    fn rejects_special_use_names() {
        assert!(validate_federation_hostname("localhost").is_err());
        assert!(validate_federation_hostname("foo.local").is_err());
        assert!(validate_federation_hostname("svc.internal").is_err());
        assert!(validate_federation_hostname("metadata.google.internal").is_err());
    }

    #[test]
    fn classifies_private_ips() {
        assert!(!is_public_ip("10.0.0.1".parse().unwrap()));
        assert!(!is_public_ip("192.168.1.1".parse().unwrap()));
        assert!(!is_public_ip("127.0.0.1".parse().unwrap()));
        assert!(!is_public_ip("169.254.169.254".parse().unwrap()));
        assert!(!is_public_ip("100.64.0.1".parse().unwrap()));
        assert!(!is_public_ip("::1".parse().unwrap()));
        assert!(!is_public_ip("fc00::1".parse().unwrap()));
        assert!(!is_public_ip("fe80::1".parse().unwrap()));
        // 8.8.8.8 is public
        assert!(is_public_ip("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn localhost_resolve_blocked() {
        // Even if someone bypassed name block, resolve of "localhost" is private.
        // validate_federation_hostname already blocks; assert_hostname_resolves_public too.
        assert!(assert_hostname_resolves_public("localhost").is_err());
    }
}
