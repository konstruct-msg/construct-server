fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/");

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
    ];

    tonic_prost_build::configure()
        // .build_server(true)  // Включи, если нужны серверные stubs
        // .build_client(true)  // Включи, если нужны клиентские stubs (по умолчанию true)
        // .out_dir("src/generated")  // Если хочешь генерировать в отдельную папку
        .compile_protos(&proto_files, &["proto/"])?;

    Ok(())
}
