#!/bin/bash
# UFW firewall rules for production

# Reset UFW
ufw --force reset

# Default policies
ufw default deny incoming
ufw default allow outgoing

# Allow SSH
ufw allow ssh

# Allow HTTP/HTTPS (only on gateway)
ufw allow 80
ufw allow 443

# Allow internal service communication (if needed)
# ufw allow from 10.0.0.0/8 to any port 8080

# Enable UFW
ufw --force enable
