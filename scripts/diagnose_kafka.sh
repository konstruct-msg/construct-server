#!/bin/bash
# Kafka Diagnostic Script
# Проверяет состояние Kafka интеграции

set -e

echo "=========================================="
echo "Kafka Diagnostic Script"
echo "=========================================="
echo ""

# Load .env if it exists
if [ -f .env ]; then
    echo "Loading .env file..."
    export $(cat .env | grep -v '^#' | xargs)
fi

# Check if Kafka is enabled
echo "1. Checking KAFKA_ENABLED..."
if [ "$KAFKA_ENABLED" = "true" ]; then
    echo "   ✅ KAFKA_ENABLED=true"
else
    echo "   ⚠️  KAFKA_ENABLED is not 'true' (current: ${KAFKA_ENABLED:-not set})"
    echo "   → Kafka producer will be created as disabled (dummy)"
    echo "   → Messages will NOT be sent to Kafka!"
    exit 1
fi

# Check Kafka brokers
echo ""
echo "2. Checking KAFKA_BROKERS..."
if [ -z "$KAFKA_BROKERS" ]; then
    echo "   ❌ KAFKA_BROKERS is not set!"
    echo "   → Default will be used: localhost:9092"
    KAFKA_BROKERS="localhost:9092"
else
    echo "   ✅ KAFKA_BROKERS=$KAFKA_BROKERS"
fi

# Check Kafka topic
echo ""
echo "3. Checking KAFKA_TOPIC..."
if [ -z "$KAFKA_TOPIC" ]; then
    echo "   ⚠️  KAFKA_TOPIC is not set (default: construct-messages)"
    KAFKA_TOPIC="construct-messages"
else
    echo "   ✅ KAFKA_TOPIC=$KAFKA_TOPIC"
fi

# Check SSL configuration
echo ""
echo "4. Checking Kafka SSL configuration..."
if [ "$KAFKA_SSL_ENABLED" = "true" ]; then
    echo "   ✅ KAFKA_SSL_ENABLED=true"
else
    echo "   ⚠️  KAFKA_SSL_ENABLED is not 'true' (current: ${KAFKA_SSL_ENABLED:-not set})"
    echo "   → Using plaintext connection (only for local development)"
fi

# Check SASL configuration
echo ""
echo "5. Checking Kafka SASL configuration..."
if [ -n "$KAFKA_SASL_USERNAME" ] && [ -n "$KAFKA_SASL_PASSWORD" ]; then
    echo "   ✅ KAFKA_SASL_USERNAME is set"
    echo "   ✅ KAFKA_SASL_PASSWORD is set"
    if [ -n "$KAFKA_SASL_MECHANISM" ]; then
        echo "   ✅ KAFKA_SASL_MECHANISM=$KAFKA_SASL_MECHANISM"
    else
        echo "   ⚠️  KAFKA_SASL_MECHANISM is not set (default: PLAIN)"
    fi
else
    echo "   ⚠️  SASL credentials not set (will use no authentication)"
fi

# Test Kafka connection (if kcat/kafkacat is available)
echo ""
echo "6. Testing Kafka connection..."
if command -v kcat &> /dev/null || command -v kafkacat &> /dev/null; then
    KCAT_CMD=$(command -v kcat || command -v kafkacat)
    echo "   Using: $KCAT_CMD"
    
    # Build kcat command
    KCAT_ARGS="-b $KAFKA_BROKERS -L"
    
    if [ "$KAFKA_SSL_ENABLED" = "true" ]; then
        KCAT_ARGS="$KCAT_ARGS -X security.protocol=SSL"
        if [ -n "$KAFKA_SASL_USERNAME" ] && [ -n "$KAFKA_SASL_PASSWORD" ]; then
            KCAT_ARGS="$KCAT_ARGS -X security.protocol=SASL_SSL"
        fi
    elif [ -n "$KAFKA_SASL_USERNAME" ] && [ -n "$KAFKA_SASL_PASSWORD" ]; then
        KCAT_ARGS="$KCAT_ARGS -X security.protocol=SASL_PLAINTEXT"
    fi
    
    if [ -n "$KAFKA_SASL_USERNAME" ] && [ -n "$KAFKA_SASL_PASSWORD" ]; then
        KCAT_ARGS="$KCAT_ARGS -X sasl.mechanisms=${KAFKA_SASL_MECHANISM:-PLAIN}"
        KCAT_ARGS="$KCAT_ARGS -X sasl.username=$KAFKA_SASL_USERNAME"
        KCAT_ARGS="$KCAT_ARGS -X sasl.password=$KAFKA_SASL_PASSWORD"
    fi
    
    echo "   Command: $KCAT_CMD $KCAT_ARGS"
    
    if timeout 5 $KCAT_CMD $KCAT_ARGS 2>&1; then
        echo "   ✅ Successfully connected to Kafka!"
    else
        echo "   ❌ Failed to connect to Kafka!"
        echo "   → Check that Kafka broker is running and accessible"
        echo "   → Check network connectivity"
        echo "   → Check credentials (if using SASL)"
    fi
else
    echo "   ⚠️  kcat/kafkacat not found (install for connection testing)"
    echo "   → macOS: brew install kcat"
    echo "   → Ubuntu: apt-get install kafkacat"
fi

# Check consumer group
echo ""
echo "7. Checking KAFKA_CONSUMER_GROUP..."
if [ -z "$KAFKA_CONSUMER_GROUP" ]; then
    echo "   ⚠️  KAFKA_CONSUMER_GROUP is not set (default: construct-delivery-workers)"
else
    echo "   ✅ KAFKA_CONSUMER_GROUP=$KAFKA_CONSUMER_GROUP"
fi

# Summary
echo ""
echo "=========================================="
echo "Summary"
echo "=========================================="
if [ "$KAFKA_ENABLED" = "true" ]; then
    echo "✅ Kafka is ENABLED"
    echo ""
    echo "Next steps:"
    echo "1. Make sure delivery_worker is running:"
    echo "   cargo run --bin delivery_worker"
    echo ""
    echo "2. Check server logs for Kafka errors:"
    echo "   Look for 'Kafka write FAILED' or 'Failed to send message to Kafka'"
    echo ""
    echo "3. Check delivery_worker logs:"
    echo "   Look for 'Kafka consumer initialized' and message processing logs"
    echo ""
    echo "4. Verify messages are being written to Kafka:"
    echo "   Check Kafka topic: $KAFKA_TOPIC"
    echo "   Use: kcat -b $KAFKA_BROKERS -t $KAFKA_TOPIC -C"
else
    echo "❌ Kafka is DISABLED"
    echo ""
    echo "To enable Kafka:"
    echo "1. Set KAFKA_ENABLED=true in .env"
    echo "2. Configure KAFKA_BROKERS"
    echo "3. Configure KAFKA_TOPIC (optional, default: construct-messages)"
    echo "4. If using SASL/SSL, configure credentials"
    echo "5. Restart the server"
fi
echo ""
