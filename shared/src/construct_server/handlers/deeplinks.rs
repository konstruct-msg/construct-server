// ============================================================================
// Deep Links Handler - Universal Links & App Links
// ============================================================================
//
// Provides deep linking functionality for sharing user profiles:
// - https://konstruct.cc/u/alice → Opens profile in app or shows web page
// - Apple Universal Links configuration
// - Android App Links configuration
//
// ============================================================================

use axum::{
    extract::{Path, State},
    response::{Html, IntoResponse, Response},
    http::StatusCode,
};
use serde_json::json;
use crate::context::AppContext;

/// Apple App Site Association file
/// Served at: /.well-known/apple-app-site-association
pub async fn apple_app_site_association(
    State(ctx): State<AppContext>,
) -> Response {
    let team_id = ctx.config.deeplinks.apple_team_id.clone();
    let bundle_id = ctx.config.apns.bundle_id.clone();

    let aasa = json!({
        "applinks": {
            "apps": [],
            "details": [{
                "appID": format!("{}.{}", team_id, bundle_id),
                "paths": ["/u/*", "/invite/*", "/group/*"]
            }]
        },
        "webcredentials": {
            "apps": [format!("{}.{}", team_id, bundle_id)]
        }
    });

    // SECURITY: Handle JSON serialization errors gracefully
    let json_body = match serde_json::to_string_pretty(&aasa) {
        Ok(body) => body,
        Err(e) => {
            tracing::error!(error = %e, "Failed to serialize Apple App Site Association JSON");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to generate configuration".to_string(),
            ).into_response();
        }
    };

    (
        StatusCode::OK,
        [("Content-Type", "application/json")],
        json_body,
    ).into_response()
}

/// Android Asset Links file
/// Served at: /.well-known/assetlinks.json
pub async fn android_asset_links(
    State(ctx): State<AppContext>,
) -> Response {
    let package_name = ctx.config.deeplinks.android_package_name.clone();
    let cert_fingerprint = ctx.config.deeplinks.android_cert_fingerprint.clone();

    let asset_links = json!([{
        "relation": ["delegate_permission/common.handle_all_urls"],
        "target": {
            "namespace": "android_app",
            "package_name": package_name,
            "sha256_cert_fingerprints": [cert_fingerprint]
        }
    }]);

    // SECURITY: Handle JSON serialization errors gracefully
    let json_body = match serde_json::to_string_pretty(&asset_links) {
        Ok(body) => body,
        Err(e) => {
            tracing::error!(error = %e, "Failed to serialize Android Asset Links JSON");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to generate configuration".to_string(),
            ).into_response();
        }
    };

    (
        StatusCode::OK,
        [("Content-Type", "application/json")],
        json_body,
    ).into_response()
}

/// User profile deep link
/// Served at: /u/:username
///
/// If accessed from mobile device with app installed:
/// - iOS: Universal Link opens app
/// - Android: App Link opens app
///
/// If accessed from browser or app not installed:
/// - Shows web page with QR code and download button
pub async fn user_profile_link(
    Path(username): Path<String>,
    State(ctx): State<AppContext>,
) -> Response {
    // Look up user by username
    let user = match lookup_user_by_username(&ctx, &username).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            return render_not_found(&username).into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, username = %username, "Failed to lookup user");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Server error").into_response();
        }
    };

    // Generate federation ID
    let federation_id = ctx.config.federation_id(&user.id);

    // Generate QR code
    let qr_svg = generate_qr_svg(&federation_id);

    // Render HTML page
    render_profile_page(&username, &federation_id, &qr_svg, &ctx.config.deep_link_base_url)
        .into_response()
}

/// Look up user by username
async fn lookup_user_by_username(
    ctx: &AppContext,
    username: &str,
) -> Result<Option<UserInfo>, sqlx::Error> {
    sqlx::query_as!(
        UserInfo,
        "SELECT id, username FROM users WHERE username = $1",
        username
    )
    .fetch_optional(&*ctx.db_pool)
    .await
}

struct UserInfo {
    id: uuid::Uuid,
    username: String,
}

/// Generate QR code as SVG
fn generate_qr_svg(data: &str) -> String {
    use qrcode::{QrCode, render::svg};

    match QrCode::new(data) {
        Ok(code) => {
            code.render()
                .min_dimensions(200, 200)
                .dark_color(svg::Color("#000000"))
                .light_color(svg::Color("#ffffff"))
                .build()
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to generate QR code");
            String::from("<svg></svg>")
        }
    }
}

/// Render profile page HTML
fn render_profile_page(
    username: &str,
    federation_id: &str,
    qr_svg: &str,
    download_url: &str,
) -> Html<String> {
    let html = format!(r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>@{username} on Konstruct</title>

    <!-- Open Graph (Facebook, LinkedIn, etc.) -->
    <meta property="og:title" content="@{username} on Konstruct">
    <meta property="og:description" content="Connect with @{username} on Konstruct - secure, private messaging">
    <meta property="og:type" content="profile">
    <meta property="og:url" content="{download_url}/u/{username}">
    <meta property="og:image" content="{download_url}/og-image.png">

    <!-- Twitter Card -->
    <meta name="twitter:card" content="summary">
    <meta name="twitter:title" content="@{username} on Konstruct">
    <meta name="twitter:description" content="Connect with @{username} on Konstruct">
    <meta name="twitter:image" content="{download_url}/og-image.png">

    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }}

        .card {{
            background: white;
            border-radius: 16px;
            padding: 40px;
            max-width: 400px;
            width: 100%;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            text-align: center;
        }}

        .logo {{
            width: 80px;
            height: 80px;
            background: #007AFF;
            border-radius: 20px;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 20px;
            font-size: 48px;
            font-weight: bold;
            color: white;
        }}

        h1 {{
            font-size: 32px;
            margin-bottom: 8px;
            color: #1a1a1a;
        }}

        .user-id {{
            color: #666;
            font-size: 14px;
            margin-bottom: 30px;
            word-break: break-all;
        }}

        .qr-container {{
            background: #f5f5f5;
            border-radius: 12px;
            padding: 20px;
            margin: 20px 0;
            display: inline-block;
        }}

        .qr-code {{
            width: 200px;
            height: 200px;
        }}

        .instruction {{
            color: #666;
            font-size: 14px;
            margin: 20px 0;
        }}

        .download-button {{
            display: inline-block;
            background: #007AFF;
            color: white;
            padding: 14px 28px;
            border-radius: 8px;
            text-decoration: none;
            font-weight: 600;
            font-size: 16px;
            margin-top: 20px;
            transition: background 0.2s;
        }}

        .download-button:hover {{
            background: #0051D5;
        }}

        .footer {{
            margin-top: 30px;
            color: #999;
            font-size: 12px;
        }}

        @media (max-width: 480px) {{
            .card {{
                padding: 30px 20px;
            }}

            h1 {{
                font-size: 28px;
            }}

            .logo {{
                width: 60px;
                height: 60px;
                font-size: 36px;
            }}
        }}
    </style>
</head>
<body>
    <div class="card">
        <div class="logo">K</div>
        <h1>@{username}</h1>
        <div class="user-id">{federation_id}</div>

        <div class="qr-container">
            <div class="qr-code">{qr_svg}</div>
        </div>

        <p class="instruction">
            Scan this QR code with the Konstruct app to connect
        </p>

        <a href="{download_url}/download" class="download-button">
            Download Konstruct
        </a>

        <div class="footer">
            Secure, private messaging
        </div>
    </div>
</body>
</html>
    "#,
        username = username,
        federation_id = federation_id,
        qr_svg = qr_svg,
        download_url = download_url,
    );

    Html(html)
}

/// Render 404 page
fn render_not_found(username: &str) -> Html<String> {
    let html = format!(r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Not Found - Konstruct</title>
    <style>
        body {{
            font-family: -apple-system, sans-serif;
            text-align: center;
            padding: 40px;
            background: #f5f5f5;
        }}

        .card {{
            max-width: 400px;
            margin: 100px auto;
            background: white;
            padding: 40px;
            border-radius: 12px;
        }}

        h1 {{ font-size: 48px; margin: 0; color: #666; }}
        p {{ color: #999; margin-top: 20px; }}
    </style>
</head>
<body>
    <div class="card">
        <h1>404</h1>
        <p>User @{username} not found</p>
    </div>
</body>
</html>
    "#, username = username);

    Html(html)
}
