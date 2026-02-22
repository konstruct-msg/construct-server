# Terraform configuration for Construct Server production deployment
# Provider: DigitalOcean VPS

terraform {
  required_providers {
    digitalocean = {
      source  = "digitalocean/digitalocean"
      version = "~> 2.0"
    }
  }
}

# Configure the DigitalOcean Provider
provider "digitalocean" {
  token = var.do_token
}

# Create a new SSH key for the droplet
resource "digitalocean_ssh_key" "construct_ssh" {
  name       = "construct-server-key"
  public_key = file(var.ssh_public_key_path)
}

# ============================================================================
# VPS INSTANCES
# ============================================================================

# API Gateway + Load Balancer Server
resource "digitalocean_droplet" "gateway_server" {
  image    = var.droplet_image
  name     = "${var.droplet_name}-gateway"
  region   = var.region
  size     = var.gateway_droplet_size
  ssh_keys = [digitalocean_ssh_key.construct_ssh.fingerprint]

  user_data = templatefile("${path.module}/cloud-init.yml", {
    admin_username = var.admin_username
    server_role    = "gateway"
  })

  tags = ["construct-server", "gateway", "load-balancer"]
}

# Application Services Server (Auth, User, Notification)
resource "digitalocean_droplet" "app_server" {
  image    = var.droplet_image
  name     = "${var.droplet_name}-app"
  region   = var.region
  size     = var.app_droplet_size
  ssh_keys = [digitalocean_ssh_key.construct_ssh.fingerprint]

  user_data = templatefile("${path.module}/cloud-init.yml", {
    admin_username = var.admin_username
    server_role    = "app"
  })

  tags = ["construct-server", "app", "services"]
}

# Database Server (PostgreSQL + Redis Primary)
resource "digitalocean_droplet" "db_server" {
  image    = var.droplet_image
  name     = "${var.droplet_name}-db"
  region   = var.region
  size     = var.db_droplet_size
  ssh_keys = [digitalocean_ssh_key.construct_ssh.fingerprint]

  user_data = templatefile("${path.module}/cloud-init.yml", {
    admin_username = var.admin_username
    server_role    = "db"
  })

  tags = ["construct-server", "database", "postgres", "redis"]
}

# Message Services + Queue Server
resource "digitalocean_droplet" "message_server" {
  image    = var.droplet_image
  name     = "${var.droplet_name}-message"
  region   = var.region
  size     = var.message_droplet_size
  ssh_keys = [digitalocean_ssh_key.construct_ssh.fingerprint]

  user_data = templatefile("${path.module}/cloud-init.yml", {
    admin_username = var.admin_username
    server_role    = "message"
  })

  tags = ["construct-server", "message", "queue"]
}

# Optional: Media + Monitoring Server
resource "digitalocean_droplet" "media_server" {
  count    = var.enable_media_server ? 1 : 0
  image    = var.droplet_image
  name     = "${var.droplet_name}-media"
  region   = var.region
  size     = var.media_droplet_size
  ssh_keys = [digitalocean_ssh_key.construct_ssh.fingerprint]

  user_data = templatefile("${path.module}/cloud-init.yml", {
    admin_username = var.admin_username
    server_role    = "media"
  })

  tags = ["construct-server", "media", "monitoring"]
}

# ============================================================================
# FIREWALL CONFIGURATION
# ============================================================================

# Gateway Server Firewall
resource "digitalocean_firewall" "gateway_firewall" {
  name = "construct-gateway-firewall"

  droplet_ids = [digitalocean_droplet.gateway_server.id]

  # Inbound rules - Gateway handles external traffic
  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    source_addresses = var.ssh_allowed_ips
  }

  inbound_rule {
    protocol         = "tcp"
    port_range       = "80"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  inbound_rule {
    protocol         = "tcp"
    port_range       = "443"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  # Outbound - allow all
  outbound_rule {
    protocol              = "tcp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "udp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
}

# Application Server Firewall
resource "digitalocean_firewall" "app_firewall" {
  name = "construct-app-firewall"

  droplet_ids = [digitalocean_droplet.app_server.id]

  # SSH access
  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    source_addresses = var.ssh_allowed_ips
  }

  # Internal service ports (from gateway only)
  inbound_rule {
    protocol         = "tcp"
    port_range       = "8001-8004"  # Auth, User, Notification services
    source_addresses = [digitalocean_droplet.gateway_server.ipv4_address_private]
  }

  # Outbound - allow all
  outbound_rule {
    protocol              = "tcp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "udp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
}

# Database Server Firewall
resource "digitalocean_firewall" "db_firewall" {
  name = "construct-db-firewall"

  droplet_ids = [digitalocean_droplet.db_server.id]

  # SSH access
  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    source_addresses = var.ssh_allowed_ips
  }

  # Database access (from application servers only)
  inbound_rule {
    protocol         = "tcp"
    port_range       = "5432"  # PostgreSQL
    source_addresses = [
      digitalocean_droplet.app_server.ipv4_address_private,
      digitalocean_droplet.message_server.ipv4_address_private,
      var.enable_media_server ? digitalocean_droplet.media_server[0].ipv4_address_private : "192.168.0.0/16"
    ]
  }

  # Redis access (from application servers only)
  inbound_rule {
    protocol         = "tcp"
    port_range       = "6379"  # Redis
    source_addresses = [
      digitalocean_droplet.app_server.ipv4_address_private,
      digitalocean_droplet.message_server.ipv4_address_private,
      var.enable_media_server ? digitalocean_droplet.media_server[0].ipv4_address_private : "192.168.0.0/16"
    ]
  }

  # Outbound - allow all
  outbound_rule {
    protocol              = "tcp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "udp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
}

# Message Server Firewall (Messaging + Queue)
resource "digitalocean_firewall" "message_firewall" {
  name = "construct-message-firewall"

  droplet_ids = [digitalocean_droplet.message_server.id]

  # SSH access
  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    source_addresses = var.ssh_allowed_ips
  }

  # Internal service ports (from gateway only)
  inbound_rule {
    protocol         = "tcp"
    port_range       = "8002"  # Messaging service
    source_addresses = [digitalocean_droplet.gateway_server.ipv4_address_private]
  }

  # Redpanda/Kafka ports (internal access)
  inbound_rule {
    protocol         = "tcp"
    port_range       = "9092"  # Kafka broker
    source_addresses = [
      digitalocean_droplet.gateway_server.ipv4_address_private,
      digitalocean_droplet.core_server.ipv4_address_private,
      digitalocean_droplet.message_server.ipv4_address_private,
      var.enable_media_server ? digitalocean_droplet.media_server[0].ipv4_address_private : "192.168.0.0/16"
    ]
  }

  # Redis replica access
  inbound_rule {
    protocol         = "tcp"
    port_range       = "6379"  # Redis
    source_addresses = [
      digitalocean_droplet.gateway_server.ipv4_address_private,
      digitalocean_droplet.app_server.ipv4_address_private,
      digitalocean_droplet.db_server.ipv4_address_private,
      digitalocean_droplet.message_server.ipv4_address_private,
      var.enable_media_server ? digitalocean_droplet.media_server[0].ipv4_address_private : "192.168.0.0/16"
    ]
  }

  # Outbound - allow all
  outbound_rule {
    protocol              = "tcp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "udp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
}

# Media Server Firewall (Optional)
resource "digitalocean_firewall" "media_firewall" {
  count = var.enable_media_server ? 1 : 0
  name  = "construct-media-firewall"

  droplet_ids = [digitalocean_droplet.media_server[0].id]

  # SSH access
  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    source_addresses = var.ssh_allowed_ips
  }

  # Media service port (from gateway)
  inbound_rule {
    protocol         = "tcp"
    port_range       = "8005"  # Media service
    source_addresses = [digitalocean_droplet.gateway_server.ipv4_address_private]
  }

  # Monitoring ports (Grafana, Prometheus)
  inbound_rule {
    protocol         = "tcp"
    port_range       = "3000"  # Grafana
    source_addresses = var.ssh_allowed_ips  # Admin access only
  }

  inbound_rule {
    protocol         = "tcp"
    port_range       = "9090"  # Prometheus
    source_addresses = var.ssh_allowed_ips  # Admin access only
  }

  # Outbound - allow all
  outbound_rule {
    protocol              = "tcp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "udp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
}

  # Inbound rules
  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    source_addresses = var.ssh_allowed_ips
  }

  inbound_rule {
    protocol         = "tcp"
    port_range       = "80"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  inbound_rule {
    protocol         = "tcp"
    port_range       = "443"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  # Allow health checks from DigitalOcean monitoring
  inbound_rule {
    protocol         = "tcp"
    port_range       = "8080"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  # Outbound rules - allow all outbound
  outbound_rule {
    protocol              = "tcp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "udp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "icmp"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
}

# ============================================================================
# DOMAIN CONFIGURATION
# ============================================================================

# Create domain if provided
resource "digitalocean_domain" "construct_domain" {
  count = var.domain_name != "" ? 1 : 0
  name  = var.domain_name
}

# Main domain points to gateway server
resource "digitalocean_record" "construct_a_record" {
  count  = var.domain_name != "" ? 1 : 0
  domain = digitalocean_domain.construct_domain[0].name
  type   = "A"
  name   = "@"
  value  = digitalocean_droplet.gateway_server.ipv4_address
}

resource "digitalocean_record" "construct_www_record" {
  count  = var.domain_name != "" ? 1 : 0
  domain = digitalocean_domain.construct_domain[0].name
  type   = "A"
  name   = "www"
  value  = digitalocean_droplet.gateway_server.ipv4_address
}

# Internal DNS records for service discovery
resource "digitalocean_record" "app_internal_record" {
  count  = var.domain_name != "" ? 1 : 0
  domain = digitalocean_domain.construct_domain[0].name
  type   = "A"
  name   = "app.internal"
  value  = digitalocean_droplet.app_server.ipv4_address_private
}

resource "digitalocean_record" "db_internal_record" {
  count  = var.domain_name != "" ? 1 : 0
  domain = digitalocean_domain.construct_domain[0].name
  type   = "A"
  name   = "db.internal"
  value  = digitalocean_droplet.db_server.ipv4_address_private
}

resource "digitalocean_record" "message_internal_record" {
  count  = var.domain_name != "" ? 1 : 0
  domain = digitalocean_domain.construct_domain[0].name
  type   = "A"
  name   = "message.internal"
  value  = digitalocean_droplet.message_server.ipv4_address_private
}

resource "digitalocean_record" "media_internal_record" {
  count  = var.enable_media_server && var.domain_name != "" ? 1 : 0
  domain = digitalocean_domain.construct_domain[0].name
  type   = "A"
  name   = "media.internal"
  value  = digitalocean_droplet.media_server[0].ipv4_address_private
}