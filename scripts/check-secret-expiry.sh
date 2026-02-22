#!/bin/bash
# Check which secrets need rotation based on creation date
# Usage: ./scripts/check-secret-expiry.sh

set -e

echo "🔍 Checking secret expiry status..."
echo ""

# Rotation schedules (in days)
CSRF_ROTATION=90
JWT_ROTATION=180
DB_ROTATION=180
KEYS_ROTATION=90

# Get current date
NOW=$(date +%s)

# Function to check secret age
check_secret() {
    local secret_name=$1
    local rotation_days=$2
    
    # Get secret creation date
    if docker secret inspect "$secret_name" >/dev/null 2>&1; then
        created=$(docker secret inspect "$secret_name" --format='{{.CreatedAt}}')
        created_ts=$(date -j -f "%Y-%m-%dT%H:%M:%S" "$(echo $created | cut -d'.' -f1)" +%s 2>/dev/null || echo "0")
        
        if [ "$created_ts" != "0" ]; then
            age_days=$(( ($NOW - $created_ts) / 86400 ))
            days_left=$(( $rotation_days - $age_days ))
            
            if [ $days_left -lt 0 ]; then
                echo "❌ $secret_name: OVERDUE by ${days_left#-} days"
            elif [ $days_left -lt 30 ]; then
                echo "⚠️  $secret_name: $days_left days until rotation"
            else
                echo "✅ $secret_name: $days_left days until rotation"
            fi
        else
            echo "⚠️  $secret_name: Unable to determine age"
        fi
    else
        echo "❓ $secret_name: Not found"
    fi
}

# Check all critical secrets
echo "Checking production secrets:"
echo ""

check_secret "construct_production_csrf_secret_v1" $CSRF_ROTATION
check_secret "construct_production_jwt_private_key_v1" $JWT_ROTATION
check_secret "construct_production_database_url_v1" $DB_ROTATION
check_secret "construct_production_delivery_secret_key_v1" $KEYS_ROTATION
check_secret "construct_production_media_hmac_secret_v1" $KEYS_ROTATION

echo ""
echo "📅 Rotation Schedule:"
echo "  - CSRF secrets: Every $CSRF_ROTATION days"
echo "  - JWT keys: Every $JWT_ROTATION days"
echo "  - Database credentials: Every $DB_ROTATION days"
echo "  - Encryption keys: Every $KEYS_ROTATION days"
echo ""
echo "💡 To rotate a secret: ./scripts/rotate-secret.sh <secret_name>"
