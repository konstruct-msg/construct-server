/// construct-ice-keygen — generate a persistent ICE_SERVER_KEY for the gateway.
///
/// Usage:
///   cargo run -p gateway --bin construct-ice-keygen
///
/// Output (ready to paste into docker-compose or .env):
///   ICE_SERVER_KEY=<base64>
///   Bridge cert: <cert>
///   Bridge line: Bridge obfs4 <YOUR_IP>:<PORT> cert=<cert> iat-mode=0
fn main() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    let cfg = construct_ice::ServerConfig::generate();
    let key_b64 = STANDARD.encode(cfg.to_bytes());
    let cert = cfg.bridge_cert();

    println!();
    println!("┌─────────────────────────────────────────────────────────────────┐");
    println!("│             construct-ice  ·  Key Generator                     │");
    println!("└─────────────────────────────────────────────────────────────────┘");
    println!();
    println!("Add both values to docker-compose.yml for gateway AND auth-service:");
    println!();
    println!("  ICE_ENABLED=true");
    println!("  ICE_SERVER_KEY={key_b64}");
    println!();
    println!("Bridge cert (for client SDK / QR codes):");
    println!("  {cert}");
    println!();
    println!("Example bridge line (replace <YOUR_IP> and <PORT>):");
    println!("  Bridge obfs4 <YOUR_IP>:9443 cert={cert} iat-mode=0");
    println!();
    println!("⚠  Keep ICE_SERVER_KEY secret. Regenerating it invalidates all");
    println!("   existing client bridge certs.");
    println!();
}
