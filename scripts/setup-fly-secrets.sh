
#!/bin/bash
set -e

# Путь к конфигу и имя приложения
FLY_CONFIG="ops/fly.toml"
APP_NAME="construct-server-staging"

if [ ! -f .env ]; then
  echo "Error: .env file not found"
  exit 1
fi

echo "=== Loading and validating secrets from .env ==="
source .env

# --- Функция для чтения PEM из файла, если указан путь ---
load_pem() {
  local var_name=$1
  local value="${!var_name}"
  if [[ "$value" == *"/"* ]] || [[ "$value" == *".pem"* ]]; then
    if [ -f "$value" ]; then
      echo "🔍 Reading $var_name from file: $value"
      eval "$var_name=\"\$(cat \"$value\")\""
    else
      echo "❌ Error: File for $var_name not found: $value"
      exit 1
    fi
  fi
}

# Обработка JWT ключей
load_pem "JWT_PUBLIC_KEY"
load_pem "JWT_PRIVATE_KEY"

# Проверка формата
if [[ "$JWT_PUBLIC_KEY" != *"-----BEGIN"* ]]; then
  echo "❌ Error: JWT_PUBLIC_KEY is not valid PEM content!"
  exit 1
fi

echo "✅ Secrets validated. Sending to Fly.io..."

# --- Установка всех секретов одним пакетом ---
# Мы собираем все переменные, которые нужны вашим 5 процессам
flyctl secrets set \
  DATABASE_URL="$DATABASE_URL" \
  REDIS_URL="$REDIS_URL" \
  JWT_PUBLIC_KEY="$JWT_PUBLIC_KEY" \
  JWT_PRIVATE_KEY="$JWT_PRIVATE_KEY" \
  JWT_ISSUER="$JWT_ISSUER" \
  CSRF_SECRET="$CSRF_SECRET" \
  SERVER_SIGNING_KEY="$SERVER_SIGNING_KEY" \
  MEDIA_HMAC_SECRET="$MEDIA_HMAC_SECRET" \
  LOG_HASH_SALT="$LOG_HASH_SALT" \
  ONLINE_CHANNEL="$ONLINE_CHANNEL" \
  DELIVERY_QUEUE_PREFIX="$DELIVERY_QUEUE_PREFIX" \
  OFFLINE_QUEUE_PREFIX="$OFFLINE_QUEUE_PREFIX" \
  DELIVERY_SECRET_KEY="$DELIVERY_SECRET_KEY" \
  DELIVERY_ACK_MODE="$DELIVERY_ACK_MODE" \
  DELIVERY_EXPIRY_DAYS="$DELIVERY_EXPIRY_DAYS" \
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
  APNS_DEVICE_TOKEN_ENCRYPTION_KEY="$APNS_DEVICE_TOKEN_ENCRYPTION_KEY" \
  APNS_ENABLED="$APNS_ENABLED" \
  APNS_ENVIRONMENT="${APNS_ENVIRONMENT:-production}" \
  APNS_KEY_ID="$APNS_KEY_ID" \
  APNS_TEAM_ID="$APNS_TEAM_ID" \
  APNS_BUNDLE_ID="$APNS_BUNDLE_ID" \
  APNS_TOPIC="$APNS_TOPIC" \
  -c $FLY_CONFIG

echo ""
echo "🚀 All secrets set for $APP_NAME"
