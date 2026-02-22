#!/bin/bash
# Setup Fly.io secrets for Construct Messenger
# This script reads values from .env and sets them as Fly.io secrets
#
# Usage:
#   ./ops/setup-fly-secrets.sh [service]
#
# Services:
#   worker - construct-delivery-worker
#   media-service - construct-media-service
#   api-gateway - construct-api-gateway
#   auth-service - construct-auth-service
#   user-service - construct-user-service
#   messaging-service - construct-messaging-service
#   notification-service - construct-notification-service
#   (no argument) - all microservices + worker
#
# JWT Configuration (RS256 only):
#   - auth-service: Requires JWT_PRIVATE_KEY + JWT_PUBLIC_KEY (can sign and verify)
#   - Other services: Require JWT_PUBLIC_KEY only (verify-only mode)
#
# Generate RSA keypair:
#   openssl genrsa -out private.pem 4096
#   openssl rsa -in private.pem -pubout -out public.pem
#
# Set in .env:
#   JWT_PRIVATE_KEY="$(cat private.pem)"
#   JWT_PUBLIC_KEY="$(cat public.pem)"

set -e

# Check if .env exists
if [ ! -f .env ]; then
  echo "Error: .env file not found"
  exit 1
fi

# Load .env file
source .env

# Get service name from argument
SERVICE="${1:-all}"

echo "=== Setting up Fly.io secrets from .env ==="
echo "Service: $SERVICE"
echo ""

# ============================================================================
# Validate and load JWT keys (RS256 only)
# ============================================================================
# IMPORTANT: If JWT_PUBLIC_KEY or JWT_PRIVATE_KEY look like file paths,
# we MUST read the actual PEM content from the file before setting secrets.
# Otherwise Fly.io will receive the PATH string, and the container won't have the file!
# ============================================================================

if [ -z "$JWT_PUBLIC_KEY" ]; then
  echo "Error: JWT_PUBLIC_KEY is required but not set in .env"
  echo ""
  echo "Generate RSA keypair with:"
  echo "  openssl genrsa -out prkeys/jwt_private_key.pem 4096"
  echo "  openssl rsa -in prkeys/jwt_private_key.pem -pubout -out prkeys/jwt_public_key.pem"
  echo ""
  echo "Then set in .env:"
  echo '  JWT_PRIVATE_KEY="$(cat prkeys/jwt_private_key.pem)"'
  echo '  JWT_PUBLIC_KEY="$(cat prkeys/jwt_public_key.pem)"'
  echo ""
  echo "Or use paths (script will read files automatically):"
  echo '  JWT_PRIVATE_KEY=prkeys/jwt_private_key.pem'
  echo '  JWT_PUBLIC_KEY=prkeys/jwt_public_key.pem'
  exit 1
fi

# Auto-detect and load JWT keys from files if they look like paths
# This prevents accidentally setting Fly.io secrets to file paths instead of PEM content
if [[ "$JWT_PUBLIC_KEY" == *"/"* ]] || [[ "$JWT_PUBLIC_KEY" == *".pem"* ]]; then
  echo "🔍 Detected JWT_PUBLIC_KEY as file path: $JWT_PUBLIC_KEY"
  if [ -f "$JWT_PUBLIC_KEY" ]; then
    echo "✅ Reading JWT public key from file..."
    JWT_PUBLIC_KEY=$(cat "$JWT_PUBLIC_KEY")
  else
    echo "❌ Error: JWT_PUBLIC_KEY file not found: $JWT_PUBLIC_KEY"
    exit 1
  fi
fi

if [ -n "$JWT_PRIVATE_KEY" ]; then
  if [[ "$JWT_PRIVATE_KEY" == *"/"* ]] || [[ "$JWT_PRIVATE_KEY" == *".pem"* ]]; then
    echo "🔍 Detected JWT_PRIVATE_KEY as file path: $JWT_PRIVATE_KEY"
    if [ -f "$JWT_PRIVATE_KEY" ]; then
      echo "✅ Reading JWT private key from file..."
      JWT_PRIVATE_KEY=$(cat "$JWT_PRIVATE_KEY")
    else
      echo "❌ Error: JWT_PRIVATE_KEY file not found: $JWT_PRIVATE_KEY"
      exit 1
    fi
  fi
fi

# Validate that JWT keys are actual PEM content, not paths
if [[ "$JWT_PUBLIC_KEY" != *"-----BEGIN"* ]]; then
  echo "❌ Error: JWT_PUBLIC_KEY doesn't look like PEM content!"
  echo "   Value starts with: ${JWT_PUBLIC_KEY:0:50}..."
  echo ""
  echo "   Make sure .env contains either:"
  echo "   1. Path to file: JWT_PUBLIC_KEY=prkeys/jwt_public_key.pem"
  echo "   2. PEM content: JWT_PUBLIC_KEY=\"\$(cat prkeys/jwt_public_key.pem)\""
  exit 1
fi

# Warn if auth-service is being set up without private key
if [ "$SERVICE" = "all" ] || [ "$SERVICE" = "auth-service" ]; then
  if [ -z "$JWT_PRIVATE_KEY" ]; then
    echo "⚠️  Warning: JWT_PRIVATE_KEY not set - auth-service won't be able to create tokens!"
    echo "   Set JWT_PRIVATE_KEY in .env for auth-service to work properly."
    echo ""
  elif [[ "$JWT_PRIVATE_KEY" != *"-----BEGIN"* ]]; then
    echo "❌ Error: JWT_PRIVATE_KEY doesn't look like PEM content!"
    echo "   Value starts with: ${JWT_PRIVATE_KEY:0:50}..."
    exit 1
  fi
fi

echo "✅ JWT keys validated - ready to set secrets"
echo ""

# ============================================================================
# Service-specific secret setup
# ============================================================================
# Note: Monolithic server (construct-server) and message-gateway removed
# All clients now use REST API through microservices

if [ "$SERVICE" = "all" ] || [ "$SERVICE" = "worker" ]; then
  echo ""
  echo "Setting up core secrets for construct-delivery-worker..."
  flyctl secrets set \
    DATABASE_URL="$DATABASE_URL" \
    REDIS_URL="$REDIS_URL" \
    JWT_PUBLIC_KEY="$JWT_PUBLIC_KEY" \
    JWT_ISSUER="$JWT_ISSUER" \
    LOG_HASH_SALT="$LOG_HASH_SALT" \
    ONLINE_CHANNEL="$ONLINE_CHANNEL" \
    DELIVERY_QUEUE_PREFIX="$DELIVERY_QUEUE_PREFIX" \
    OFFLINE_QUEUE_PREFIX="$OFFLINE_QUEUE_PREFIX" \
    CSRF_ENABLED="false" \
    --app construct-delivery-worker
  fi

# ============================================================================
# Kafka secrets (if enabled)
# ============================================================================

if [ "$KAFKA_ENABLED" = "true" ]; then
  # Kafka secrets are set per-service below (messaging-service, worker)

  if [ "$SERVICE" = "all" ] || [ "$SERVICE" = "worker" ]; then
    echo ""
    echo "Setting up Kafka secrets for construct-delivery-worker..."
    flyctl secrets set \
      KAFKA_ENABLED="$KAFKA_ENABLED" \
      KAFKA_BROKERS="$KAFKA_BROKERS" \
      KAFKA_TOPIC="$KAFKA_TOPIC" \
      KAFKA_CONSUMER_GROUP="$KAFKA_CONSUMER_GROUP" \
      KAFKA_SSL_ENABLED="$KAFKA_SSL_ENABLED" \
      KAFKA_SASL_MECHANISM="$KAFKA_SASL_MECHANISM" \
      KAFKA_SASL_USERNAME="$KAFKA_SASL_USERNAME" \
      KAFKA_SASL_PASSWORD="$KAFKA_SASL_PASSWORD" \
      KAFKA_PRODUCER_COMPRESSION="$KAFKA_PRODUCER_COMPRESSION" \
      KAFKA_PRODUCER_ACKS="$KAFKA_PRODUCER_ACKS" \
      ${KAFKA_PRODUCER_LINGER_MS:+KAFKA_PRODUCER_LINGER_MS="$KAFKA_PRODUCER_LINGER_MS"} \
      ${KAFKA_PRODUCER_BATCH_SIZE:+KAFKA_PRODUCER_BATCH_SIZE="$KAFKA_PRODUCER_BATCH_SIZE"} \
      ${KAFKA_PRODUCER_MAX_IN_FLIGHT:+KAFKA_PRODUCER_MAX_IN_FLIGHT="$KAFKA_PRODUCER_MAX_IN_FLIGHT"} \
      ${KAFKA_PRODUCER_RETRIES:+KAFKA_PRODUCER_RETRIES="$KAFKA_PRODUCER_RETRIES"} \
      ${KAFKA_PRODUCER_REQUEST_TIMEOUT_MS:+KAFKA_PRODUCER_REQUEST_TIMEOUT_MS="$KAFKA_PRODUCER_REQUEST_TIMEOUT_MS"} \
      ${KAFKA_PRODUCER_DELIVERY_TIMEOUT_MS:+KAFKA_PRODUCER_DELIVERY_TIMEOUT_MS="$KAFKA_PRODUCER_DELIVERY_TIMEOUT_MS"} \
      ${KAFKA_PRODUCER_ENABLE_IDEMPOTENCE:+KAFKA_PRODUCER_ENABLE_IDEMPOTENCE="$KAFKA_PRODUCER_ENABLE_IDEMPOTENCE"} \
      --app construct-delivery-worker
  fi
fi

# ============================================================================
# APNs, Federation, Delivery ACK, Key Management
# ============================================================================
# These are now handled per-service below (notification-service, etc.)

# Delivery ACK secrets (if enabled) - only for worker
if [ -n "$DELIVERY_ACK_MODE" ] && [ "$DELIVERY_ACK_MODE" != "disabled" ]; then
  if [ "$SERVICE" = "all" ] || [ "$SERVICE" = "worker" ]; then
    echo ""
    echo "Setting up Delivery ACK secrets for construct-delivery-worker..."
    flyctl secrets set \
      DELIVERY_ACK_MODE="$DELIVERY_ACK_MODE" \
      DELIVERY_SECRET_KEY="$DELIVERY_SECRET_KEY" \
      DELIVERY_EXPIRY_DAYS="$DELIVERY_EXPIRY_DAYS" \
      --app construct-delivery-worker
  fi
fi

# ============================================================================
# Key Management System secrets (if enabled)
# ============================================================================
#
# IMPORTANT: Key Management System requires RS256 (RSA keys), not HS256 (JWT_SECRET)
# - JWT_PRIVATE_KEY and JWT_PUBLIC_KEY must be set for services using Key Management
# - Key Management System uses Vault Transit engine with RSA-4096 keys
# - JWT_SECRET (HS256) is not compatible with automatic key rotation
#
# Migration path:
# 1. Generate RSA keypair: openssl genrsa -out private.pem 4096
# 2. Extract public key: openssl rsa -in private.pem -pubout -out public.pem
# 3. Set JWT_PRIVATE_KEY and JWT_PUBLIC_KEY in .env
# 4. Set VAULT_ADDR and authentication (VAULT_TOKEN or VAULT_K8S_ROLE)
# 5. Initialize keys in Vault (see docs/KEY_MANAGEMENT_PRODUCTION.md)
# ============================================================================

if [ -n "$VAULT_ADDR" ]; then
  # Key Management System is enabled - set secrets for all services that use it
  echo ""
  echo "Setting up Key Management System secrets..."
  
  # Check if RS256 keys are set (required for Key Management System)
  if [ -z "$JWT_PRIVATE_KEY" ] || [ -z "$JWT_PUBLIC_KEY" ]; then
    echo ""
    echo "⚠️  WARNING: Key Management System requires RS256 (JWT_PRIVATE_KEY/JWT_PUBLIC_KEY)"
    echo "   JWT_SECRET (HS256) is not compatible with automatic key rotation"
    echo ""
    echo "   To enable Key Management System:"
    echo "   1. Generate RSA keypair:"
    echo "      openssl genrsa -out private.pem 4096"
    echo "      openssl rsa -in private.pem -pubout -out public.pem"
    echo "   2. Set in .env:"
    echo "      JWT_PRIVATE_KEY=\"\$(cat private.pem)\""
    echo "      JWT_PUBLIC_KEY=\"\$(cat public.pem)\""
    echo "   3. Re-run this script"
    echo ""
    echo "   Key Management System will be disabled until RS256 keys are configured."
  fi

  # Key Management secrets are set per-service below (auth-service, messaging-service, etc.)

  # Set secrets for construct-auth-service
  if [ "$SERVICE" = "all" ] || [ "$SERVICE" = "auth-service" ]; then
    echo "Setting Key Management secrets for construct-auth-service..."
    if [ -n "$VAULT_TOKEN" ] && [ -n "$VAULT_K8S_ROLE" ]; then
      flyctl secrets set \
        VAULT_ADDR="$VAULT_ADDR" \
        VAULT_TOKEN="$VAULT_TOKEN" \
        VAULT_K8S_ROLE="$VAULT_K8S_ROLE" \
        ${KEY_REFRESH_INTERVAL_SECS:+KEY_REFRESH_INTERVAL_SECS="$KEY_REFRESH_INTERVAL_SECS"} \
        ${KEY_GRACE_PERIOD_SECS:+KEY_GRACE_PERIOD_SECS="$KEY_GRACE_PERIOD_SECS"} \
        ${KEY_AUTO_ROTATION_ENABLED:+KEY_AUTO_ROTATION_ENABLED="$KEY_AUTO_ROTATION_ENABLED"} \
        --app construct-auth-service
    elif [ -n "$VAULT_TOKEN" ]; then
      flyctl secrets set \
        VAULT_ADDR="$VAULT_ADDR" \
        VAULT_TOKEN="$VAULT_TOKEN" \
        ${KEY_REFRESH_INTERVAL_SECS:+KEY_REFRESH_INTERVAL_SECS="$KEY_REFRESH_INTERVAL_SECS"} \
        ${KEY_GRACE_PERIOD_SECS:+KEY_GRACE_PERIOD_SECS="$KEY_GRACE_PERIOD_SECS"} \
        ${KEY_AUTO_ROTATION_ENABLED:+KEY_AUTO_ROTATION_ENABLED="$KEY_AUTO_ROTATION_ENABLED"} \
        --app construct-auth-service
    elif [ -n "$VAULT_K8S_ROLE" ]; then
      flyctl secrets set \
        VAULT_ADDR="$VAULT_ADDR" \
        VAULT_K8S_ROLE="$VAULT_K8S_ROLE" \
        ${KEY_REFRESH_INTERVAL_SECS:+KEY_REFRESH_INTERVAL_SECS="$KEY_REFRESH_INTERVAL_SECS"} \
        ${KEY_GRACE_PERIOD_SECS:+KEY_GRACE_PERIOD_SECS="$KEY_GRACE_PERIOD_SECS"} \
        ${KEY_AUTO_ROTATION_ENABLED:+KEY_AUTO_ROTATION_ENABLED="$KEY_AUTO_ROTATION_ENABLED"} \
        --app construct-auth-service
    else
      flyctl secrets set \
        VAULT_ADDR="$VAULT_ADDR" \
        ${KEY_REFRESH_INTERVAL_SECS:+KEY_REFRESH_INTERVAL_SECS="$KEY_REFRESH_INTERVAL_SECS"} \
        ${KEY_GRACE_PERIOD_SECS:+KEY_GRACE_PERIOD_SECS="$KEY_GRACE_PERIOD_SECS"} \
        ${KEY_AUTO_ROTATION_ENABLED:+KEY_AUTO_ROTATION_ENABLED="$KEY_AUTO_ROTATION_ENABLED"} \
        --app construct-auth-service
    fi
  fi

  # Set secrets for construct-messaging-service
  if [ "$SERVICE" = "all" ] || [ "$SERVICE" = "messaging-service" ]; then
    echo "Setting Key Management secrets for construct-messaging-service..."
    if [ -n "$VAULT_TOKEN" ] && [ -n "$VAULT_K8S_ROLE" ]; then
      flyctl secrets set \
        VAULT_ADDR="$VAULT_ADDR" \
        VAULT_TOKEN="$VAULT_TOKEN" \
        VAULT_K8S_ROLE="$VAULT_K8S_ROLE" \
        ${KEY_REFRESH_INTERVAL_SECS:+KEY_REFRESH_INTERVAL_SECS="$KEY_REFRESH_INTERVAL_SECS"} \
        ${KEY_GRACE_PERIOD_SECS:+KEY_GRACE_PERIOD_SECS="$KEY_GRACE_PERIOD_SECS"} \
        ${KEY_AUTO_ROTATION_ENABLED:+KEY_AUTO_ROTATION_ENABLED="$KEY_AUTO_ROTATION_ENABLED"} \
        --app construct-messaging-service
    elif [ -n "$VAULT_TOKEN" ]; then
      flyctl secrets set \
        VAULT_ADDR="$VAULT_ADDR" \
        VAULT_TOKEN="$VAULT_TOKEN" \
        ${KEY_REFRESH_INTERVAL_SECS:+KEY_REFRESH_INTERVAL_SECS="$KEY_REFRESH_INTERVAL_SECS"} \
        ${KEY_GRACE_PERIOD_SECS:+KEY_GRACE_PERIOD_SECS="$KEY_GRACE_PERIOD_SECS"} \
        ${KEY_AUTO_ROTATION_ENABLED:+KEY_AUTO_ROTATION_ENABLED="$KEY_AUTO_ROTATION_ENABLED"} \
        --app construct-messaging-service
    elif [ -n "$VAULT_K8S_ROLE" ]; then
      flyctl secrets set \
        VAULT_ADDR="$VAULT_ADDR" \
        VAULT_K8S_ROLE="$VAULT_K8S_ROLE" \
        ${KEY_REFRESH_INTERVAL_SECS:+KEY_REFRESH_INTERVAL_SECS="$KEY_REFRESH_INTERVAL_SECS"} \
        ${KEY_GRACE_PERIOD_SECS:+KEY_GRACE_PERIOD_SECS="$KEY_GRACE_PERIOD_SECS"} \
        ${KEY_AUTO_ROTATION_ENABLED:+KEY_AUTO_ROTATION_ENABLED="$KEY_AUTO_ROTATION_ENABLED"} \
        --app construct-messaging-service
    else
      flyctl secrets set \
        VAULT_ADDR="$VAULT_ADDR" \
        ${KEY_REFRESH_INTERVAL_SECS:+KEY_REFRESH_INTERVAL_SECS="$KEY_REFRESH_INTERVAL_SECS"} \
        ${KEY_GRACE_PERIOD_SECS:+KEY_GRACE_PERIOD_SECS="$KEY_GRACE_PERIOD_SECS"} \
        ${KEY_AUTO_ROTATION_ENABLED:+KEY_AUTO_ROTATION_ENABLED="$KEY_AUTO_ROTATION_ENABLED"} \
        --app construct-messaging-service
    fi
  fi

  # Set secrets for construct-notification-service
  if [ "$SERVICE" = "all" ] || [ "$SERVICE" = "notification-service" ]; then
    echo "Setting Key Management secrets for construct-notification-service..."
    if [ -n "$VAULT_TOKEN" ] && [ -n "$VAULT_K8S_ROLE" ]; then
      flyctl secrets set \
        VAULT_ADDR="$VAULT_ADDR" \
        VAULT_TOKEN="$VAULT_TOKEN" \
        VAULT_K8S_ROLE="$VAULT_K8S_ROLE" \
        ${KEY_REFRESH_INTERVAL_SECS:+KEY_REFRESH_INTERVAL_SECS="$KEY_REFRESH_INTERVAL_SECS"} \
        ${KEY_GRACE_PERIOD_SECS:+KEY_GRACE_PERIOD_SECS="$KEY_GRACE_PERIOD_SECS"} \
        ${KEY_AUTO_ROTATION_ENABLED:+KEY_AUTO_ROTATION_ENABLED="$KEY_AUTO_ROTATION_ENABLED"} \
        --app construct-notification-service
    elif [ -n "$VAULT_TOKEN" ]; then
      flyctl secrets set \
        VAULT_ADDR="$VAULT_ADDR" \
        VAULT_TOKEN="$VAULT_TOKEN" \
        ${KEY_REFRESH_INTERVAL_SECS:+KEY_REFRESH_INTERVAL_SECS="$KEY_REFRESH_INTERVAL_SECS"} \
        ${KEY_GRACE_PERIOD_SECS:+KEY_GRACE_PERIOD_SECS="$KEY_GRACE_PERIOD_SECS"} \
        ${KEY_AUTO_ROTATION_ENABLED:+KEY_AUTO_ROTATION_ENABLED="$KEY_AUTO_ROTATION_ENABLED"} \
        --app construct-notification-service
    elif [ -n "$VAULT_K8S_ROLE" ]; then
      flyctl secrets set \
        VAULT_ADDR="$VAULT_ADDR" \
        VAULT_K8S_ROLE="$VAULT_K8S_ROLE" \
        ${KEY_REFRESH_INTERVAL_SECS:+KEY_REFRESH_INTERVAL_SECS="$KEY_REFRESH_INTERVAL_SECS"} \
        ${KEY_GRACE_PERIOD_SECS:+KEY_GRACE_PERIOD_SECS="$KEY_GRACE_PERIOD_SECS"} \
        ${KEY_AUTO_ROTATION_ENABLED:+KEY_AUTO_ROTATION_ENABLED="$KEY_AUTO_ROTATION_ENABLED"} \
        --app construct-notification-service
    else
      flyctl secrets set \
        VAULT_ADDR="$VAULT_ADDR" \
        ${KEY_REFRESH_INTERVAL_SECS:+KEY_REFRESH_INTERVAL_SECS="$KEY_REFRESH_INTERVAL_SECS"} \
        ${KEY_GRACE_PERIOD_SECS:+KEY_GRACE_PERIOD_SECS="$KEY_GRACE_PERIOD_SECS"} \
        ${KEY_AUTO_ROTATION_ENABLED:+KEY_AUTO_ROTATION_ENABLED="$KEY_AUTO_ROTATION_ENABLED"} \
        --app construct-notification-service
    fi
  fi
else
  echo ""
  echo "ℹ️  Key Management System disabled (VAULT_ADDR not set)"
  echo "   To enable: Set VAULT_ADDR and either VAULT_TOKEN or VAULT_K8S_ROLE in .env"
fi

# ============================================================================
# Message Gateway removed - was only used for WebSocket message processing
# REST API routes send directly to Kafka
# ============================================================================

# ============================================================================
# Microservices secrets
# ============================================================================

if [ "$SERVICE" = "all" ] || [ "$SERVICE" = "api-gateway" ]; then
  echo ""
  echo "Setting up secrets for construct-api-gateway..."
  # Create app if it doesn't exist
  if ! flyctl status --app construct-api-gateway >/dev/null 2>&1; then
    echo "Creating construct-api-gateway app..."
    flyctl apps create construct-api-gateway
  fi
  # Base secrets
  # Note: CSRF_SECRET is required for API Gateway (it uses CSRF protection middleware)
  # If CSRF_SECRET is not set, generate it automatically
  if [ -z "$CSRF_SECRET" ]; then
    echo "⚠️  CSRF_SECRET not set - generating random secret..."
    CSRF_SECRET=$(openssl rand -hex 32)
  fi
  
  flyctl secrets set \
    DATABASE_URL="$DATABASE_URL" \
    REDIS_URL="$REDIS_URL" \
    JWT_PRIVATE_KEY="$JWT_PRIVATE_KEY" \
    JWT_PUBLIC_KEY="$JWT_PUBLIC_KEY" \
    JWT_ISSUER="$JWT_ISSUER" \
    LOG_HASH_SALT="$LOG_HASH_SALT" \
    ONLINE_CHANNEL="$ONLINE_CHANNEL" \
    DELIVERY_QUEUE_PREFIX="$DELIVERY_QUEUE_PREFIX" \
    OFFLINE_QUEUE_PREFIX="$OFFLINE_QUEUE_PREFIX" \
    CSRF_SECRET="$CSRF_SECRET" \
    --app construct-api-gateway
fi

if [ "$SERVICE" = "all" ] || [ "$SERVICE" = "auth-service" ]; then
  echo ""
  echo "Setting up secrets for construct-auth-service..."
  # Create app if it doesn't exist
  if ! flyctl status --app construct-auth-service >/dev/null 2>&1; then
    echo "Creating construct-auth-service app..."
    flyctl apps create construct-auth-service
  fi
  # Note: CSRF_ENABLED=false because auth-service doesn't use CSRF middleware
  # (CSRF is handled by API Gateway)
  flyctl secrets set \
    DATABASE_URL="$DATABASE_URL" \
    REDIS_URL="$REDIS_URL" \
    JWT_PRIVATE_KEY="$JWT_PRIVATE_KEY" \
    JWT_PUBLIC_KEY="$JWT_PUBLIC_KEY" \
    JWT_ISSUER="$JWT_ISSUER" \
    LOG_HASH_SALT="$LOG_HASH_SALT" \
    ONLINE_CHANNEL="$ONLINE_CHANNEL" \
    DELIVERY_QUEUE_PREFIX="$DELIVERY_QUEUE_PREFIX" \
    OFFLINE_QUEUE_PREFIX="$OFFLINE_QUEUE_PREFIX" \
    CSRF_ENABLED="false" \
    --app construct-auth-service
fi

if [ "$SERVICE" = "all" ] || [ "$SERVICE" = "user-service" ]; then
  echo ""
  echo "Setting up secrets for construct-user-service..."
  # Create app if it doesn't exist
  if ! flyctl status --app construct-user-service >/dev/null 2>&1; then
    echo "Creating construct-user-service app..."
    flyctl apps create construct-user-service
  fi
  # Note: CSRF_ENABLED=false because user-service doesn't use CSRF middleware
  # (CSRF is handled by API Gateway)
  flyctl secrets set \
    DATABASE_URL="$DATABASE_URL" \
    REDIS_URL="$REDIS_URL" \
    JWT_PUBLIC_KEY="$JWT_PUBLIC_KEY" \
    JWT_ISSUER="$JWT_ISSUER" \
    LOG_HASH_SALT="$LOG_HASH_SALT" \
    ONLINE_CHANNEL="$ONLINE_CHANNEL" \
    DELIVERY_QUEUE_PREFIX="$DELIVERY_QUEUE_PREFIX" \
    OFFLINE_QUEUE_PREFIX="$OFFLINE_QUEUE_PREFIX" \
    CSRF_ENABLED="false" \
    --app construct-user-service
fi

if [ "$SERVICE" = "all" ] || [ "$SERVICE" = "messaging-service" ]; then
  echo ""
  echo "Setting up secrets for construct-messaging-service..."
  # Create app if it doesn't exist
  if ! flyctl status --app construct-messaging-service >/dev/null 2>&1; then
    echo "Creating construct-messaging-service app..."
    flyctl apps create construct-messaging-service
  fi
  # Note: CSRF_ENABLED=false because messaging-service doesn't use CSRF middleware
  # (CSRF is handled by API Gateway)
  flyctl secrets set \
    DATABASE_URL="$DATABASE_URL" \
    REDIS_URL="$REDIS_URL" \
    JWT_PUBLIC_KEY="$JWT_PUBLIC_KEY" \
    JWT_ISSUER="$JWT_ISSUER" \
    LOG_HASH_SALT="$LOG_HASH_SALT" \
    ONLINE_CHANNEL="$ONLINE_CHANNEL" \
    DELIVERY_QUEUE_PREFIX="$DELIVERY_QUEUE_PREFIX" \
    OFFLINE_QUEUE_PREFIX="$OFFLINE_QUEUE_PREFIX" \
    CSRF_ENABLED="false" \
    ${MAX_LONG_POLL_REQUESTS_PER_WINDOW:+MAX_LONG_POLL_REQUESTS_PER_WINDOW="$MAX_LONG_POLL_REQUESTS_PER_WINDOW"} \
    ${LONG_POLL_RATE_LIMIT_WINDOW_SECS:+LONG_POLL_RATE_LIMIT_WINDOW_SECS="$LONG_POLL_RATE_LIMIT_WINDOW_SECS"} \
    --app construct-messaging-service

  # Kafka secrets for Messaging Service
  if [ "$KAFKA_ENABLED" = "true" ]; then
    flyctl secrets set \
      KAFKA_ENABLED="$KAFKA_ENABLED" \
      KAFKA_BROKERS="$KAFKA_BROKERS" \
      KAFKA_TOPIC="$KAFKA_TOPIC" \
      KAFKA_CONSUMER_GROUP="$KAFKA_CONSUMER_GROUP" \
      KAFKA_SSL_ENABLED="$KAFKA_SSL_ENABLED" \
      KAFKA_SASL_MECHANISM="$KAFKA_SASL_MECHANISM" \
      KAFKA_SASL_USERNAME="$KAFKA_SASL_USERNAME" \
      KAFKA_SASL_PASSWORD="$KAFKA_SASL_PASSWORD" \
      KAFKA_PRODUCER_COMPRESSION="$KAFKA_PRODUCER_COMPRESSION" \
      KAFKA_PRODUCER_ACKS="$KAFKA_PRODUCER_ACKS" \
      ${KAFKA_PRODUCER_LINGER_MS:+KAFKA_PRODUCER_LINGER_MS="$KAFKA_PRODUCER_LINGER_MS"} \
      ${KAFKA_PRODUCER_BATCH_SIZE:+KAFKA_PRODUCER_BATCH_SIZE="$KAFKA_PRODUCER_BATCH_SIZE"} \
      ${KAFKA_PRODUCER_MAX_IN_FLIGHT:+KAFKA_PRODUCER_MAX_IN_FLIGHT="$KAFKA_PRODUCER_MAX_IN_FLIGHT"} \
      ${KAFKA_PRODUCER_RETRIES:+KAFKA_PRODUCER_RETRIES="$KAFKA_PRODUCER_RETRIES"} \
      ${KAFKA_PRODUCER_REQUEST_TIMEOUT_MS:+KAFKA_PRODUCER_REQUEST_TIMEOUT_MS="$KAFKA_PRODUCER_REQUEST_TIMEOUT_MS"} \
      ${KAFKA_PRODUCER_DELIVERY_TIMEOUT_MS:+KAFKA_PRODUCER_DELIVERY_TIMEOUT_MS="$KAFKA_PRODUCER_DELIVERY_TIMEOUT_MS"} \
      ${KAFKA_PRODUCER_ENABLE_IDEMPOTENCE:+KAFKA_PRODUCER_ENABLE_IDEMPOTENCE="$KAFKA_PRODUCER_ENABLE_IDEMPOTENCE"} \
      --app construct-messaging-service
  fi

  # APNs device token encryption key (required for federation features)
  if [ -n "$APNS_DEVICE_TOKEN_ENCRYPTION_KEY" ] && [ "$APNS_DEVICE_TOKEN_ENCRYPTION_KEY" != "CHANGE_ME_GENERATE_WITH_OPENSSL_RAND_HEX_32" ] && [ "$APNS_DEVICE_TOKEN_ENCRYPTION_KEY" != "0000000000000000000000000000000000000000000000000000000000000000" ]; then
    flyctl secrets set \
      APNS_DEVICE_TOKEN_ENCRYPTION_KEY="$APNS_DEVICE_TOKEN_ENCRYPTION_KEY" \
      --app construct-messaging-service
  else
    echo "⚠️  Warning: APNS_DEVICE_TOKEN_ENCRYPTION_KEY not set or is default value"
    echo "   Messaging Service requires this key for federation features."
    echo "   Generate with: openssl rand -hex 32"
    echo "   Then set in .env and run: make secrets-messaging-service"
  fi

  # Optional: Full APNs configuration (only if APNs is enabled)
  if [ -n "$APNS_ENABLED" ] && [ "$APNS_ENABLED" = "true" ]; then
    flyctl secrets set \
      APNS_ENABLED="$APNS_ENABLED" \
      APNS_ENVIRONMENT="${APNS_ENVIRONMENT:-production}" \
      --app construct-messaging-service

    if [ -n "$APNS_KEY_ID" ]; then
      flyctl secrets set \
        APNS_KEY_ID="$APNS_KEY_ID" \
        APNS_TEAM_ID="$APNS_TEAM_ID" \
        APNS_BUNDLE_ID="$APNS_BUNDLE_ID" \
        APNS_TOPIC="$APNS_TOPIC" \
        --app construct-messaging-service

      if [ -n "$APNS_KEY_PATH" ]; then
        flyctl secrets set \
          APNS_KEY_PATH="$APNS_KEY_PATH" \
          --app construct-messaging-service
      fi
    fi
  fi
fi

if [ "$SERVICE" = "all" ] || [ "$SERVICE" = "notification-service" ]; then
  echo ""
  echo "Setting up secrets for construct-notification-service..."
  # Create app if it doesn't exist
  if ! flyctl status --app construct-notification-service >/dev/null 2>&1; then
    echo "Creating construct-notification-service app..."
    flyctl apps create construct-notification-service
  fi
  # Note: CSRF_ENABLED=false because notification-service doesn't use CSRF middleware
  # (CSRF is handled by API Gateway)
  flyctl secrets set \
    DATABASE_URL="$DATABASE_URL" \
    REDIS_URL="$REDIS_URL" \
    JWT_ISSUER="$JWT_ISSUER" \
    JWT_PUBLIC_KEY="$JWT_PUBLIC_KEY" \
    LOG_HASH_SALT="$LOG_HASH_SALT" \
    ONLINE_CHANNEL="$ONLINE_CHANNEL" \
    DELIVERY_QUEUE_PREFIX="$DELIVERY_QUEUE_PREFIX" \
    OFFLINE_QUEUE_PREFIX="$OFFLINE_QUEUE_PREFIX" \
    CSRF_ENABLED="false" \
    --app construct-notification-service

  # APNs device token encryption key (REQUIRED for Notification Service, even if APNs is disabled)
  # This key is used to encrypt device tokens in the database
  if [ -n "$APNS_DEVICE_TOKEN_ENCRYPTION_KEY" ] && [ "$APNS_DEVICE_TOKEN_ENCRYPTION_KEY" != "CHANGE_ME_GENERATE_WITH_OPENSSL_RAND_HEX_32" ] && [ "$APNS_DEVICE_TOKEN_ENCRYPTION_KEY" != "0000000000000000000000000000000000000000000000000000000000000000" ]; then
    flyctl secrets set \
      APNS_DEVICE_TOKEN_ENCRYPTION_KEY="$APNS_DEVICE_TOKEN_ENCRYPTION_KEY" \
      --app construct-notification-service
  else
    echo "⚠️  Warning: APNS_DEVICE_TOKEN_ENCRYPTION_KEY not set or is default value"
    echo "   Notification Service requires this key to encrypt device tokens."
    echo "   Generate with: openssl rand -hex 32"
    echo "   Then set in .env and run: make secrets-notification-service"
  fi

  # Optional: APNs configuration (only if APNs is enabled)
  if [ -n "$APNS_ENABLED" ] && [ "$APNS_ENABLED" = "true" ]; then
    flyctl secrets set \
      APNS_ENABLED="$APNS_ENABLED" \
      APNS_ENVIRONMENT="${APNS_ENVIRONMENT:-production}" \
      --app construct-notification-service

    if [ -n "$APNS_KEY_ID" ]; then
      flyctl secrets set \
        APNS_KEY_ID="$APNS_KEY_ID" \
        APNS_TEAM_ID="$APNS_TEAM_ID" \
        APNS_BUNDLE_ID="$APNS_BUNDLE_ID" \
        APNS_TOPIC="$APNS_TOPIC" \
        --app construct-notification-service

      if [ -n "$APNS_KEY_PATH" ]; then
        flyctl secrets set \
          APNS_KEY_PATH="$APNS_KEY_PATH" \
          --app construct-notification-service
     fi
   fi

  fi
fi

if [ "$SERVICE" = "all" ] || [ "$SERVICE" = "media-service" ]; then
  echo ""
  echo "Setting up secrets for construct-media-service..."
  # Create app if it doesn't exist
  if ! flyctl status --app construct-media-service >/dev/null 2>&1; then
    echo "Creating construct-media-service app..."
    flyctl apps create construct-media-service
  fi
  
  # Required: MEDIA_HMAC_SECRET (must match the secret used by other services to generate tokens)
  # Note: .env may use MEDIA_UPLOAD_TOKEN_SECRET for backwards compatibility
  MEDIA_HMAC_SECRET="${MEDIA_HMAC_SECRET:-$MEDIA_UPLOAD_TOKEN_SECRET}"
  if [ -z "$MEDIA_HMAC_SECRET" ]; then
    echo "⚠️  MEDIA_HMAC_SECRET not set - generating random secret..."
    MEDIA_HMAC_SECRET=$(openssl rand -hex 32)
    echo "   Generated secret: $MEDIA_HMAC_SECRET"
    echo "   ⚠️  IMPORTANT: Save this secret and use it in other services to generate upload tokens!"
  fi

  flyctl secrets set \
    MEDIA_HMAC_SECRET="$MEDIA_HMAC_SECRET" \
    ${MEDIA_ADMIN_TOKEN:+MEDIA_ADMIN_TOKEN="$MEDIA_ADMIN_TOKEN"} \
    ${MEDIA_STORAGE_DIR:+MEDIA_STORAGE_DIR="$MEDIA_STORAGE_DIR"} \
    ${MEDIA_MAX_FILE_SIZE:+MEDIA_MAX_FILE_SIZE="$MEDIA_MAX_FILE_SIZE"} \
    ${MEDIA_FILE_TTL_SECONDS:+MEDIA_FILE_TTL_SECONDS="$MEDIA_FILE_TTL_SECONDS"} \
    ${MEDIA_BIND_ADDRESS:+MEDIA_BIND_ADDRESS="$MEDIA_BIND_ADDRESS"} \
    --app construct-media-service

   # Optional: JWT public key for RS256 (only public key needed for verification)
   if [ -n "$JWT_PUBLIC_KEY" ]; then
     flyctl secrets set \
       JWT_PUBLIC_KEY="$JWT_PUBLIC_KEY" \
       --app construct-media-service
   fi
  echo "✅ Media Service secrets configured"
fi

echo ""
echo "=== ✅ All secrets have been set! ==="
echo ""
echo "To verify:"
if [ "$SERVICE" = "all" ] || [ "$SERVICE" = "worker" ]; then
  echo "  flyctl secrets list --app construct-delivery-worker"
fi
if [ "$SERVICE" = "all" ] || [ "$SERVICE" = "api-gateway" ]; then
  echo "  flyctl secrets list --app construct-api-gateway"
fi
if [ "$SERVICE" = "all" ] || [ "$SERVICE" = "auth-service" ]; then
  echo "  flyctl secrets list --app construct-auth-service"
fi
if [ "$SERVICE" = "all" ] || [ "$SERVICE" = "user-service" ]; then
  echo "  flyctl secrets list --app construct-user-service"
fi
if [ "$SERVICE" = "all" ] || [ "$SERVICE" = "messaging-service" ]; then
  echo "  flyctl secrets list --app construct-messaging-service"
fi
if [ "$SERVICE" = "all" ] || [ "$SERVICE" = "notification-service" ]; then
  echo "  flyctl secrets list --app construct-notification-service"
fi
if [ "$SERVICE" = "all" ] || [ "$SERVICE" = "media-service" ]; then
  echo "  flyctl secrets list --app construct-media-service"
fi
echo ""
echo "To deploy:"
if [ "$SERVICE" = "all" ] || [ "$SERVICE" = "worker" ]; then
  echo "  make deploy-worker"
fi
if [ "$SERVICE" = "all" ] || [ "$SERVICE" = "api-gateway" ]; then
  echo "  make deploy-api-gateway"
fi
if [ "$SERVICE" = "all" ] || [ "$SERVICE" = "auth-service" ]; then
  echo "  make deploy-auth-service"
fi
if [ "$SERVICE" = "all" ] || [ "$SERVICE" = "user-service" ]; then
  echo "  make deploy-user-service"
fi
if [ "$SERVICE" = "all" ] || [ "$SERVICE" = "messaging-service" ]; then
  echo "  make deploy-messaging-service"
fi
if [ "$SERVICE" = "all" ] || [ "$SERVICE" = "notification-service" ]; then
  echo "  make deploy-notification-service"
fi
if [ "$SERVICE" = "all" ] || [ "$SERVICE" = "media-service" ]; then
  echo "  make deploy-media-service"
fi
