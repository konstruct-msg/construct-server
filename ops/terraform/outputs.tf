# ============================================================================
# INFRASTRUCTURE OUTPUTS
# ============================================================================

output "gateway_server" {
  description = "Gateway server details"
  value = {
    name         = digitalocean_droplet.gateway_server.name
    public_ip    = digitalocean_droplet.gateway_server.ipv4_address
    private_ip   = digitalocean_droplet.gateway_server.ipv4_address_private
    ssh_command  = "ssh ${var.admin_username}@${digitalocean_droplet.gateway_server.ipv4_address}"
  }
}

output "app_server" {
  description = "Application services server details"
  value = {
    name         = digitalocean_droplet.app_server.name
    public_ip    = digitalocean_droplet.app_server.ipv4_address
    private_ip   = digitalocean_droplet.app_server.ipv4_address_private
    ssh_command  = "ssh ${var.admin_username}@${digitalocean_droplet.app_server.ipv4_address}"
  }
}

output "db_server" {
  description = "Database server details"
  value = {
    name         = digitalocean_droplet.db_server.name
    public_ip    = digitalocean_droplet.db_server.ipv4_address
    private_ip   = digitalocean_droplet.db_server.ipv4_address_private
    ssh_command  = "ssh ${var.admin_username}@${digitalocean_droplet.db_server.ipv4_address}"
  }
}

output "message_server" {
  description = "Message services server details"
  value = {
    name         = digitalocean_droplet.message_server.name
    public_ip    = digitalocean_droplet.message_server.ipv4_address
    private_ip   = digitalocean_droplet.message_server.ipv4_address_private
    ssh_command  = "ssh ${var.admin_username}@${digitalocean_droplet.message_server.ipv4_address}"
  }
}

output "media_server" {
  description = "Media server details (if enabled)"
  value = var.enable_media_server ? {
    name         = digitalocean_droplet.media_server[0].name
    public_ip    = digitalocean_droplet.media_server[0].ipv4_address
    private_ip   = digitalocean_droplet.media_server[0].ipv4_address_private
    ssh_command  = "ssh ${var.admin_username}@${digitalocean_droplet.media_server[0].ipv4_address}"
  } : null
}

output "domain_name" {
  description = "Domain name (if configured)"
  value       = var.domain_name != "" ? var.domain_name : null
}

# ============================================================================
# SERVICE ENDPOINTS
# ============================================================================

output "gateway_url" {
  description = "API Gateway URL"
  value       = var.domain_name != "" ? "https://${var.domain_name}" : "http://${digitalocean_droplet.gateway_server.ipv4_address}:80"
}

output "health_check_url" {
  description = "Health check URL"
  value       = var.domain_name != "" ? "https://${var.domain_name}/health" : "http://${digitalocean_droplet.gateway_server.ipv4_address}/health"
}

output "internal_service_urls" {
  description = "Internal service URLs for configuration"
  value = {
    auth_service      = "http://app.internal:8001"
    user_service      = "http://app.internal:8002"
    notification_svc  = "http://app.internal:8003"
    messaging_service = "http://message.internal:8004"
    media_service     = var.enable_media_server ? "http://media.internal:8005" : null
    postgres          = "postgresql://construct:${var.db_password}@db.internal:5432/construct"
    redis_primary     = "redis://db.internal:6379"
    redis_replica     = "redis://message.internal:6379"
    redpanda          = "message.internal:9092"
  }
}