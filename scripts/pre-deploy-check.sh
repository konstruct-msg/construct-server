#!/bin/bash
# Pre-deployment validation script
# Ensures code compiles and secrets are correctly configured
# Usage: ./scripts/pre-deploy-check.sh <service-name>
#
# Example:
#   ./scripts/pre-deploy-check.sh messaging-service

set -e

SERVICE="$1"

if [ -z "$SERVICE" ]; then
  echo "Usage: $0 <service-name>"
  echo ""
  echo "Available services:"
  echo "  - api-gateway"
  echo "  - auth-service"
  echo "  - user-service"
  echo "  - messaging-service"
  echo "  - notification-service"
  echo "  - media-service"
  echo "  - worker"
  exit 1
fi

# Color output
COLOR_INFO="\033[0;36m"
COLOR_SUCCESS="\033[0;32m"
COLOR_ERROR="\033[0;31m"
COLOR_RESET="\033[0m"

echo -e "${COLOR_INFO}╔══════════════════════════════════════════════════════════════════╗${COLOR_RESET}"
echo -e "${COLOR_INFO}║            🔍 PRE-DEPLOYMENT VALIDATION                          ║${COLOR_RESET}"
echo -e "${COLOR_INFO}║            Service: $SERVICE$(printf '%*s' $((39 - ${#SERVICE}))' ')║${COLOR_RESET}"
echo -e "${COLOR_INFO}╚══════════════════════════════════════════════════════════════════╝${COLOR_RESET}"
echo ""

# Map service to binary/package
case "$SERVICE" in
  api-gateway)
    BINARY="gateway"
    PACKAGE="gateway"
    ;;
  auth-service)
    BINARY="auth-service"
    PACKAGE="auth-service"
    ;;
  user-service)
    BINARY="user-service"
    PACKAGE="user-service"
    ;;
  messaging-service)
    BINARY="messaging-service"
    PACKAGE="messaging-service"
    ;;
  notification-service)
    BINARY="notification-service"
    PACKAGE="notification-service"
    ;;
  media-service)
    BINARY="media-service"
    PACKAGE="media-service"
    ;;
  worker)
    BINARY="delivery-worker"
    PACKAGE="delivery-worker"
    ;;
  *)
    echo -e "${COLOR_ERROR}❌ Unknown service: $SERVICE${COLOR_RESET}"
    exit 1
    ;;
esac

# ============================================================================
# Step 1: Check that code compiles
# ============================================================================
echo -e "${COLOR_INFO}📦 Step 1: Checking code compilation...${COLOR_RESET}"

if [ ! -f "Cargo.toml" ]; then
  echo -e "${COLOR_ERROR}❌ Cargo.toml not found${COLOR_RESET}"
  echo "   Run this script from the project root"
  exit 1
fi

# Check specific package
echo "   Checking $PACKAGE..."
if cargo check --package "$PACKAGE" --quiet 2>&1 | grep -q "error"; then
  echo -e "${COLOR_ERROR}❌ Compilation failed for $PACKAGE${COLOR_RESET}"
  echo ""
  echo "Fix compilation errors first:"
  echo "  cargo check --package $PACKAGE"
  exit 1
fi

echo -e "${COLOR_SUCCESS}   ✅ Code compiles successfully${COLOR_RESET}"
echo ""

# ============================================================================
# Step 2: Validate secrets
# ============================================================================
echo -e "${COLOR_INFO}🔐 Step 2: Validating Fly.io secrets...${COLOR_RESET}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ ! -f "$SCRIPT_DIR/validate-service-secrets.sh" ]; then
  echo -e "${COLOR_ERROR}❌ validate-service-secrets.sh not found${COLOR_RESET}"
  exit 1
fi

# Run secrets validation (will exit with error if fails)
bash "$SCRIPT_DIR/validate-service-secrets.sh" "$SERVICE"

echo ""

# ============================================================================
# Step 3: Check Dockerfile exists
# ============================================================================
echo -e "${COLOR_INFO}🐳 Step 3: Checking Dockerfile...${COLOR_RESET}"

if [ ! -f "Dockerfile" ]; then
  echo -e "${COLOR_ERROR}❌ Dockerfile not found${COLOR_RESET}"
  exit 1
fi

echo -e "${COLOR_SUCCESS}   ✅ Dockerfile exists${COLOR_RESET}"
echo ""

# ============================================================================
# Step 4: Check fly.toml exists for service
# ============================================================================
echo -e "${COLOR_INFO}✈️  Step 4: Checking fly.toml configuration...${COLOR_RESET}"

case "$SERVICE" in
  api-gateway)
    FLY_TOML="ops/fly.api-gateway.toml"
    ;;
  auth-service)
    FLY_TOML="ops/fly.auth-service.toml"
    ;;
  user-service)
    FLY_TOML="ops/fly.user-service.toml"
    ;;
  messaging-service)
    FLY_TOML="ops/fly.messaging-service.toml"
    ;;
  notification-service)
    FLY_TOML="ops/fly.notification-service.toml"
    ;;
  media-service)
    FLY_TOML="ops/fly.media.toml"
    ;;
  worker)
    FLY_TOML="ops/fly.worker.toml"
    ;;
esac

if [ ! -f "$FLY_TOML" ]; then
  echo -e "${COLOR_ERROR}❌ fly.toml not found: $FLY_TOML${COLOR_RESET}"
  exit 1
fi

echo -e "${COLOR_SUCCESS}   ✅ fly.toml found: $FLY_TOML${COLOR_RESET}"
echo ""

# ============================================================================
# All checks passed
# ============================================================================
echo -e "${COLOR_SUCCESS}╔══════════════════════════════════════════════════════════════════╗${COLOR_RESET}"
echo -e "${COLOR_SUCCESS}║            ✅ PRE-DEPLOYMENT CHECKS PASSED                       ║${COLOR_RESET}"
echo -e "${COLOR_SUCCESS}║            Ready to deploy: $SERVICE$(printf '%*s' $((32 - ${#SERVICE}))' ')║${COLOR_RESET}"
echo -e "${COLOR_SUCCESS}╚══════════════════════════════════════════════════════════════════╝${COLOR_RESET}"
echo ""
echo "Deploy with:"
echo "  make deploy-$(echo $SERVICE | sed 's/-service//')"
echo ""

exit 0
