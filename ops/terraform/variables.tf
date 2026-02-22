# Variables for Terraform configuration

variable "do_token" {
  description = "DigitalOcean API token"
  type        = string
  sensitive   = true
}

variable "ssh_public_key_path" {
  description = "Path to SSH public key file"
  type        = string
  default     = "~/.ssh/id_rsa.pub"
}

variable "ssh_allowed_ips" {
  description = "List of IP addresses allowed to SSH"
  type        = list(string)
  default     = ["0.0.0.0/0"] # WARNING: Restrict this in production
}

variable "region" {
  description = "DigitalOcean region"
  type        = string
  default     = "nyc1"
}

variable "droplet_image" {
  description = "Droplet image (OS)"
  type        = string
  default     = "ubuntu-22-04-x64"
}

variable "gateway_droplet_size" {
  description = "Gateway server droplet size (RAM/CPU)"
  type        = string
  default     = "s-1vcpu-1gb" # Smaller for gateway/load balancer
}

variable "app_droplet_size" {
  description = "Application services server droplet size (RAM/CPU)"
  type        = string
  default     = "s-2vcpu-4gb" # Auth, User, Notification services
}

variable "db_droplet_size" {
  description = "Database server droplet size (RAM/CPU)"
  type        = string
  default     = "s-2vcpu-4gb" # PostgreSQL + Redis Primary
}

variable "message_droplet_size" {
  description = "Message services server droplet size (RAM/CPU)"
  type        = string
  default     = "s-2vcpu-4gb" # Message services + Queue
}

variable "media_droplet_size" {
  description = "Media server droplet size (RAM/CPU)"
  type        = string
  default     = "s-2vcpu-4gb" # Media + monitoring
}

variable "enable_media_server" {
  description = "Enable dedicated media server"
  type        = bool
  default     = false
}

variable "droplet_name" {
  description = "Base name for droplets"
  type        = string
  default     = "construct-server"
}

variable "admin_username" {
  description = "Admin username for the server"
  type        = string
  default     = "construct"
}

variable "domain_name" {
  description = "Domain name (leave empty to skip domain setup)"
  type        = string
  default     = ""
}

# Database configuration
variable "db_password" {
  description = "Database password"
  type        = string
  sensitive   = true
}

variable "jwt_secret" {
  description = "JWT secret key"
  type        = string
  sensitive   = true
}

variable "kafka_brokers" {
  description = "Kafka brokers URL"
  type        = string
  default     = ""
}

variable "kafka_sasl_username" {
  description = "Kafka SASL username"
  type        = string
  default     = ""
}

variable "kafka_sasl_password" {
  description = "Kafka SASL password"
  type        = string
  sensitive   = true
  default     = ""
}