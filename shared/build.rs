/// Which commit this binary was built from, baked in at compile time.
///
/// The workspace semver alone could not answer "what is running?": it only moves
/// when someone runs bump-version.sh, so any number of commits share one version
/// and one image tag. On 2026-08-12 production reported 0.17.4 and the only way
/// to learn what was inside it was to search git for the commit that introduced
/// that string — which happened to be HEAD. That is luck, not a method.
///
/// In Docker the SHA arrives as the GIT_SHA build-arg (CI passes github.sha).
/// Outside Docker we ask git directly, so a local build is also identifiable.
/// Neither available — a source tarball — reports "unknown" rather than lying.
fn emit_build_info() {
    println!("cargo:rerun-if-env-changed=GIT_SHA");

    let sha = std::env::var("GIT_SHA")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            std::process::Command::new("git")
                .args(["rev-parse", "HEAD"])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| "unknown".to_string());

    // Short form is what a human reads in /.well-known and in Grafana.
    let short: String = sha.chars().take(12).collect();
    println!("cargo:rustc-env=CONSTRUCT_GIT_SHA={sha}");
    println!("cargo:rustc-env=CONSTRUCT_GIT_SHA_SHORT={short}");

    // RFC 3339 without pulling in a date crate for a build script.
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    println!("cargo:rustc-env=CONSTRUCT_BUILD_UNIX={secs}");
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/");
    emit_build_info();

    let proto_files = vec![
        "proto/core/identity.proto",
        "proto/core/crypto.proto",
        "proto/core/pagination.proto",
        "proto/core/envelope.proto",
        "proto/messaging/content.proto",
        "proto/messaging/e2ee.proto",
        "proto/messaging/mls.proto",
        "proto/signaling/presence.proto",
        "proto/signaling/webrtc.proto",
        "proto/services/auth_service.proto",
        "proto/services/user_service.proto",
        "proto/services/messaging_service.proto",
        "proto/services/notification_service.proto",
        "proto/services/invite_service.proto",
        "proto/services/media_service.proto",
        "proto/services/key_service.proto",
        "proto/services/mls_service.proto",
        "proto/services/channel_service.proto",
        "proto/services/sentinel_service.proto",
        "proto/services/signaling_service.proto",
        "proto/services/veil_service.proto",
    ];

    tonic_prost_build::configure()
        .build_server(true)
        // .build_client(true)  // Включи, если нужны клиентские stubs (по умолчанию true)
        // .out_dir("src/generated")  // Если хочешь генерировать в отдельную папку
        .compile_protos(&proto_files, &["proto/"])?;

    Ok(())
}
