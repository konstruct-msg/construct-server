#!/bin/bash
# First-time Let's Encrypt certificate setup
# Usage: ./ops/scripts/init-ssl.sh your-domain.com your@email.com
set -e

DOMAIN=${1:?Usage: $0 DOMAIN EMAIL}
EMAIL=${2:?Usage: $0 DOMAIN EMAIL}

echo "==> Getting SSL certificate for $DOMAIN..."

# Start nginx in HTTP-only mode for ACME challenge
docker run --rm -d --name nginx-init \
  -p 80:80 \
  -v "$(pwd)/ops/nginx/nginx-init.conf:/etc/nginx/conf.d/default.conf:ro" \
  -v certbot-www:/var/www/certbot \
  nginx:1.27-alpine

# Request certificate
docker run --rm \
  -v /etc/letsencrypt:/etc/letsencrypt \
  -v certbot-www:/var/www/certbot \
  certbot/certbot certonly \
  --webroot -w /var/www/certbot \
  --email "$EMAIL" \
  --agree-tos --no-eff-email \
  -d "$DOMAIN"

docker stop nginx-init

echo "==> Updating nginx.conf with domain $DOMAIN..."
sed -i "s/YOUR_DOMAIN/$DOMAIN/g" ops/nginx/nginx.conf

echo "==> Certificate obtained! Now run:"
echo "    docker compose -f ops/docker-compose.prod.yml up -d"
