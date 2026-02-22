#[cfg(test)]
mod tests {
    use crate::types::*;

    #[test]
    fn test_health_response_serialization() {
        let health = HealthResponse {
            status: "healthy".to_string(),
            version: "1.0.0".to_string(),
        };

        let json = serde_json::to_string(&health).unwrap();
        // Should be camelCase, but fields don't have underscores so it's same
        assert!(json.contains(r#""status""#));
        assert!(json.contains(r#""version""#));
        println!("HealthResponse: {}", json);
    }

    #[test]
    fn test_upload_response_serialization() {
        let upload = UploadResponse {
            media_id: "test123".to_string(),
            expires_at: 1234567890,
        };

        let json = serde_json::to_string(&upload).unwrap();
        // Should be mediaId (camelCase), not media_id (snake_case)
        assert!(json.contains(r#""mediaId""#));
        assert!(json.contains(r#""expiresAt""#));
        assert!(!json.contains(r#""media_id""#));
        assert!(!json.contains(r#""expires_at""#));
        println!("UploadResponse: {}", json);
    }
}
