# Vault server configuration
# Single-node, file storage — suitable for MVP/staging
# Migrate to Raft or Consul storage for production HA

storage "file" {
  path = "/vault/data"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true   # TLS handled by Traefik
}

# UI accessible via https://vault.YOUR_DOMAIN (Traefik routes it)
ui = true

# Disable mlock — required for containerized environments
disable_mlock = true

# Telemetry (optional)
# telemetry {
#   prometheus_retention_time = "30s"
# }
