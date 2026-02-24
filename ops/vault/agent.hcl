# Vault Agent configuration
# Runs as an init container: authenticates to Vault, fetches secrets,
# writes them to a shared volume as /secrets/app.env, then exits.

vault {
  address = "http://vault:8200"
}

# AppRole authentication — role_id and secret_id provided via mounted files
auto_auth {
  method "approle" {
    config = {
      role_id_file_path                   = "/vault/auth/role_id"
      secret_id_file_path                 = "/vault/auth/secret_id"
      remove_secret_id_file_after_reading = false
    }
  }

  sink "file" {
    config = {
      path = "/tmp/vault-token"
    }
  }
}

# Write all construct secrets as a shell-sourceable .env file
template {
  contents = <<EOT
{{- with secret "secret/construct" }}
DATABASE_URL="{{ .Data.data.DATABASE_URL }}"
REDIS_URL="{{ .Data.data.REDIS_URL }}"
JWT_PRIVATE_KEY="{{ .Data.data.JWT_PRIVATE_KEY }}"
JWT_PUBLIC_KEY="{{ .Data.data.JWT_PUBLIC_KEY }}"
JWT_ISSUER="{{ .Data.data.JWT_ISSUER }}"
SERVER_SIGNING_KEY="{{ .Data.data.SERVER_SIGNING_KEY }}"
CSRF_SECRET="{{ .Data.data.CSRF_SECRET }}"
MEDIA_HMAC_SECRET="{{ .Data.data.MEDIA_HMAC_SECRET }}"
LOG_HASH_SALT="{{ .Data.data.LOG_HASH_SALT }}"
DELIVERY_SECRET_KEY="{{ .Data.data.DELIVERY_SECRET_KEY }}"
APNS_BUNDLE_ID="{{ .Data.data.APNS_BUNDLE_ID }}"
APNS_KEY_ID="{{ .Data.data.APNS_KEY_ID }}"
APNS_TEAM_ID="{{ .Data.data.APNS_TEAM_ID }}"
APNS_TOPIC="{{ .Data.data.APNS_TOPIC }}"
APNS_DEVICE_TOKEN_ENCRYPTION_KEY="{{ .Data.data.APNS_DEVICE_TOKEN_ENCRYPTION_KEY }}"
{{- end }}
EOT
  destination = "/secrets/app.env"
  # Run once and exit (init container pattern)
  error_on_missing_key = true
}

# Exit after writing secrets (init container — not a long-running process)
exit_after_auth = true
