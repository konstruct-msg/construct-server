#!/bin/bash
# ============================================================================
# Redpanda TLS Setup Script for Digital Ocean VPS
# ============================================================================
# This script helps configure TLS for Redpanda on a VPS
#
# Usage:
#   1. Copy this script to your VPS
#   2. Run: chmod +x setup_redpanda_tls.sh
#   3. Run: sudo ./setup_redpanda_tls.sh
#
# Prerequisites:
#   - Redpanda installed
#   - Root/sudo access
#   - Domain name pointing to VPS (for Let's Encrypt) OR use self-signed
# ============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Redpanda TLS Setup${NC}"
echo -e "${GREEN}========================================${NC}"

# Configuration
REDPANDA_CERT_DIR="/etc/redpanda/certs"
REDPANDA_CONFIG="/etc/redpanda/redpanda.yaml"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root (sudo)${NC}"
    exit 1
fi

# Create certificate directory
mkdir -p "$REDPANDA_CERT_DIR"
chmod 700 "$REDPANDA_CERT_DIR"

echo ""
echo "Choose certificate type:"
echo "  1) Self-signed (for testing/internal use)"
echo "  2) Let's Encrypt (requires domain name)"
echo ""
read -p "Enter choice [1-2]: " cert_choice

case $cert_choice in
    1)
        echo -e "${YELLOW}Generating self-signed certificates...${NC}"

        # Get VPS IP or hostname
        read -p "Enter VPS IP address or hostname: " VPS_HOST

        # Generate CA key and certificate
        openssl genrsa -out "$REDPANDA_CERT_DIR/ca.key" 4096
        openssl req -new -x509 -days 365 -key "$REDPANDA_CERT_DIR/ca.key" \
            -out "$REDPANDA_CERT_DIR/ca.crt" \
            -subj "/CN=Redpanda CA/O=Construct/C=US"

        # Generate server key
        openssl genrsa -out "$REDPANDA_CERT_DIR/node.key" 2048

        # Create certificate signing request
        openssl req -new -key "$REDPANDA_CERT_DIR/node.key" \
            -out "$REDPANDA_CERT_DIR/node.csr" \
            -subj "/CN=$VPS_HOST/O=Construct/C=US"

        # Create extensions file for SAN
        cat > "$REDPANDA_CERT_DIR/node.ext" << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = $VPS_HOST
DNS.2 = localhost
IP.1 = $VPS_HOST
IP.2 = 127.0.0.1
EOF

        # Sign the certificate
        openssl x509 -req -in "$REDPANDA_CERT_DIR/node.csr" \
            -CA "$REDPANDA_CERT_DIR/ca.crt" \
            -CAkey "$REDPANDA_CERT_DIR/ca.key" \
            -CAcreateserial \
            -out "$REDPANDA_CERT_DIR/node.crt" \
            -days 365 \
            -extfile "$REDPANDA_CERT_DIR/node.ext"

        # Cleanup CSR and extensions
        rm -f "$REDPANDA_CERT_DIR/node.csr" "$REDPANDA_CERT_DIR/node.ext"

        echo -e "${GREEN}Self-signed certificates generated!${NC}"
        echo ""
        echo -e "${YELLOW}IMPORTANT: For self-signed certs, clients need CA certificate.${NC}"
        echo -e "Copy $REDPANDA_CERT_DIR/ca.crt to your client machines."
        ;;

    2)
        echo -e "${YELLOW}Setting up Let's Encrypt certificates...${NC}"

        read -p "Enter your domain name: " DOMAIN

        # Install certbot if not present
        if ! command -v certbot &> /dev/null; then
            echo "Installing certbot..."
            apt-get update
            apt-get install -y certbot
        fi

        # Stop Redpanda temporarily to free port 443 if needed
        echo "Obtaining Let's Encrypt certificate..."
        certbot certonly --standalone -d "$DOMAIN" --non-interactive --agree-tos --email admin@"$DOMAIN"

        # Link certificates
        ln -sf "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" "$REDPANDA_CERT_DIR/node.crt"
        ln -sf "/etc/letsencrypt/live/$DOMAIN/privkey.pem" "$REDPANDA_CERT_DIR/node.key"

        # For Let's Encrypt, CA is included in fullchain
        cp "/etc/letsencrypt/live/$DOMAIN/chain.pem" "$REDPANDA_CERT_DIR/ca.crt"

        echo -e "${GREEN}Let's Encrypt certificates configured!${NC}"
        echo ""
        echo -e "${YELLOW}NOTE: Set up auto-renewal with: certbot renew --deploy-hook 'systemctl restart redpanda'${NC}"
        ;;

    *)
        echo -e "${RED}Invalid choice${NC}"
        exit 1
        ;;
esac

# Set proper permissions
chown -R redpanda:redpanda "$REDPANDA_CERT_DIR"
chmod 600 "$REDPANDA_CERT_DIR"/*.key
chmod 644 "$REDPANDA_CERT_DIR"/*.crt

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Certificates ready!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Now update your Redpanda configuration."
echo ""
echo -e "${YELLOW}Add the following to $REDPANDA_CONFIG:${NC}"
echo ""
cat << 'YAML'
redpanda:
  kafka_api:
    - address: 0.0.0.0
      port: 9092
      authentication_method: sasl
  kafka_api_tls:
    - enabled: true
      require_client_auth: false
      cert_file: /etc/redpanda/certs/node.crt
      key_file: /etc/redpanda/certs/node.key
      truststore_file: /etc/redpanda/certs/ca.crt

  # SASL/SCRAM configuration
  superusers:
    - admin
YAML

echo ""
echo -e "${YELLOW}Then create SASL user:${NC}"
echo ""
echo "  rpk acl user create construct_user -p 'YOUR_PASSWORD' --mechanism scram-sha-256"
echo ""
echo -e "${YELLOW}And restart Redpanda:${NC}"
echo ""
echo "  sudo systemctl restart redpanda"
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Client Environment Variables${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Set these in your messaging-service:"
echo ""
echo "  KAFKA_ENABLED=true"
echo "  KAFKA_BROKERS=YOUR_VPS_IP:9092"
echo "  KAFKA_SSL_ENABLED=true"
echo "  KAFKA_SASL_MECHANISM=SCRAM-SHA-256"
echo "  KAFKA_SASL_USERNAME=construct_user"
echo "  KAFKA_SASL_PASSWORD=YOUR_PASSWORD"
echo ""

if [ "$cert_choice" = "1" ]; then
    echo -e "${YELLOW}For self-signed certificates, you also need:${NC}"
    echo ""
    echo "  KAFKA_SSL_CA_LOCATION=/path/to/ca.crt"
    echo ""
    echo -e "${RED}Copy ca.crt from VPS to your client!${NC}"
fi

echo ""
echo -e "${GREEN}Setup complete!${NC}"
