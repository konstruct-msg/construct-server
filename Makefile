# ============================================================================
# Construct Server - Makefile (Phase 4.5+ optimized)
# ============================================================================
# 
# Microservices Architecture:
# - API Gateway (routing, auth, rate limiting)
# - Auth Service (JWT, registration, login)
# - User Service (profiles, keys, contacts)
# - Messaging Service (send/receive messages, END_SESSION)
# - Notification Service (APNs push notifications)
# - Media Service (image/video upload)
# - Delivery Worker (Kafka consumer, message delivery)
#
# ============================================================================

.PHONY: help

# Default target
help:
	@echo "╔════════════════════════════════════════════════════════════════╗"
	@echo "║  Construct Server - Build & Deploy Commands (Phase 4.5+)      ║"
	@echo "╚════════════════════════════════════════════════════════════════╝"
	@echo ""
	@echo "🔨 Development:"
	@echo "  make dev             Start local stack (db + redis + kafka)"
	@echo "  make dev-down        Stop local stack"
	@echo "  make dev-logs        View local stack logs"
	@echo "  make dev-services    Start all microservices locally (Docker)"
	@echo "  make dev-services-down   Stop all microservices"
	@echo "  make dev-services-logs   View microservices logs"
	@echo "  make dev-rebuild     Rebuild and restart services"
	@echo "  make build           Build all binaries (release)"
	@echo "  make test            Run all tests"
	@echo "  make test-env-up     Start test infrastructure (Postgres + Redis + Redpanda)"
	@echo "  make test-env-down   Stop test infrastructure"
	@echo "  make test-env-logs   View test infrastructure logs"
	@echo "  make test-integration Run integration tests (requires test-env-up)"
	@echo "  make check           Run clippy + fmt check"
	@echo "  make fmt             Format code"
	@echo ""
	@echo "🚀 Deployment (Fly.io):"
	@echo "  make deploy          Deploy all microservices"
	@echo "  make deploy-gateway  Deploy API Gateway only"
	@echo "  make deploy-auth     Deploy Auth Service only"
	@echo "  make deploy-user     Deploy User Service only"
	@echo "  make deploy-msg      Deploy Messaging Service only"
	@echo "  make deploy-notif    Deploy Notification Service only"
	@echo "  make deploy-media    Deploy Media Service only"
	@echo "  make deploy-worker   Deploy Delivery Worker only"
	@echo ""
	@echo "🔐 Secrets Management:"
	@echo "  make secrets         Setup secrets for all services"
	@echo "  make secrets-<name>  Setup secrets for specific service"
	@echo "                       (gateway, auth, user, msg, notif, media, worker)"
	@echo "  make validate-secrets-<name>  Validate secrets for specific service"
	@echo ""
	@echo "✅ Pre-deployment Validation:"
	@echo "  make pre-deploy-check-<name>  Run all pre-deploy checks for service"
	@echo "                                (compilation + secrets validation)"
	@echo ""
	@echo "📊 Monitoring:"
	@echo "  make status          Show status of all services"
	@echo "  make logs            View logs of all services"
	@echo "  make logs-<name>     View logs of specific service"
	@echo "                       (gateway, auth, user, msg, notif, media, worker)"
	@echo ""
	@echo "🗄️  Database:"
	@echo "  make db-migrate      Run database migrations"
	@echo "  make db-dev          Start local PostgreSQL + Redis"
	@echo "  make db-dev-down     Stop local databases"
	@echo ""
	@echo "🔑 Security & Keys:"
	@echo "  make gen-jwt         Generate RSA keypair for RS256 JWT"
	@echo "  make vault-up        Start Vault in dev mode"
	@echo "  make vault-down      Stop Vault"
	@echo "  make vault-init      Initialize Vault with Transit keys"
	@echo ""
	@echo "💡 Quick Start:"
	@echo "  Development: make dev && make dev-logs"
	@echo "  First deploy: make secrets && make deploy"
	@echo "  Update code: make build && make deploy-msg"

# ============================================================================
# Variables
# ============================================================================

# Service names (Fly.io apps)
APP_GATEWAY = construct-api-gateway
APP_AUTH = construct-auth-service
APP_USER = construct-user-service
APP_MSG = construct-messaging-service
APP_NOTIF = construct-notification-service
APP_MEDIA = construct-media-service
APP_WORKER = construct-delivery-worker

# Docker Compose files
COMPOSE = docker-compose -f ops/docker-compose.yml
COMPOSE_KAFKA = docker-compose -f ops/docker-compose.kafka.yml
COMPOSE_DEV = docker-compose -f ops/docker-compose.dev.yml
COMPOSE_TEST = docker-compose -f ops/docker-compose.test.yml

# Colors for output
COLOR_RESET = \033[0m
COLOR_INFO = \033[0;36m
COLOR_SUCCESS = \033[0;32m
COLOR_WARNING = \033[0;33m
COLOR_ERROR = \033[0;31m

# ============================================================================
# Development
# ============================================================================

.PHONY: dev dev-down dev-logs dev-services dev-services-down dev-services-logs dev-rebuild build test check fmt clean

# Start infrastructure (PostgreSQL + Redis + Kafka)
dev:
	@echo "$(COLOR_INFO)🐳 Starting local development infrastructure...$(COLOR_RESET)"
	@if [ ! -f .env.local ]; then \
		echo "$(COLOR_WARNING)⚠️  .env.local not found, creating from example...$(COLOR_RESET)"; \
		cp .env.local.example .env.local; \
		echo "$(COLOR_INFO)💡 Edit .env.local to customize your local environment$(COLOR_RESET)"; \
	fi
	@$(COMPOSE) up -d postgres redis
	@$(COMPOSE_KAFKA) up -d kafka
	@echo ""
	@echo "$(COLOR_SUCCESS)✅ Infrastructure started:$(COLOR_RESET)"
	@echo "   PostgreSQL: localhost:5432 (user: construct, db: construct)"
	@echo "   Redis: localhost:6379"
	@echo "   Kafka: localhost:9092"
	@echo "   Kafka UI: http://localhost:8080"
	@echo ""
	@echo "$(COLOR_INFO)💡 Next steps:$(COLOR_RESET)"
	@echo "   make db-migrate          # Apply database migrations"
	@echo "   make dev-services        # Start all microservices"
	@echo "   make dev-services-logs   # View service logs"

# Stop infrastructure
dev-down:
	@echo "$(COLOR_INFO)🛑 Stopping local infrastructure...$(COLOR_RESET)"
	@$(COMPOSE) down
	@$(COMPOSE_KAFKA) down
	@echo "$(COLOR_SUCCESS)✅ Infrastructure stopped$(COLOR_RESET)"

# View infrastructure logs
dev-logs:
	@echo "$(COLOR_INFO)📋 Tailing logs from infrastructure...$(COLOR_RESET)"
	@$(COMPOSE) logs -f

# Start all microservices in Docker
dev-services:
	@echo "$(COLOR_INFO)🚀 Starting all microservices locally...$(COLOR_RESET)"
	@if [ ! -f .env.local ]; then \
		echo "$(COLOR_ERROR)❌ .env.local not found!$(COLOR_RESET)"; \
		echo "   Create it: cp .env.local.example .env.local"; \
		exit 1; \
	fi
	@echo "$(COLOR_INFO)🔨 Building Docker images...$(COLOR_RESET)"
	@$(COMPOSE_DEV) build
	@echo "$(COLOR_INFO)🚀 Starting services...$(COLOR_RESET)"
	@$(COMPOSE_DEV) up -d
	@echo ""
	@echo "$(COLOR_SUCCESS)✅ All services started:$(COLOR_RESET)"
	@echo "   API Gateway:       http://localhost:8000 (health: 8001)"
	@echo "   Auth Service:      http://localhost:8010 (health: 8011)"
	@echo "   User Service:      http://localhost:8020 (health: 8021)"
	@echo "   Messaging Service: http://localhost:8030 (health: 8031)"
	@echo "   Notification Svc:  http://localhost:8040 (health: 8041)"
	@echo "   Media Service:     http://localhost:8050 (health: 8051)"
	@echo "   Delivery Worker:   (background process)"
	@echo ""
	@echo "$(COLOR_INFO)💡 Useful commands:$(COLOR_RESET)"
	@echo "   make dev-services-logs   # View logs"
	@echo "   make dev-services-down   # Stop services"
	@echo "   make dev-rebuild         # Rebuild after code changes"

# Stop all microservices
dev-services-down:
	@echo "$(COLOR_INFO)🛑 Stopping all microservices...$(COLOR_RESET)"
	@$(COMPOSE_DEV) down
	@echo "$(COLOR_SUCCESS)✅ Services stopped$(COLOR_RESET)"

# View microservices logs
dev-services-logs:
	@echo "$(COLOR_INFO)📋 Tailing logs from all microservices...$(COLOR_RESET)"
	@$(COMPOSE_DEV) logs -f

# Rebuild and restart services after code changes
dev-rebuild:
	@echo "$(COLOR_INFO)🔄 Rebuilding and restarting services...$(COLOR_RESET)"
	@$(COMPOSE_DEV) build
	@$(COMPOSE_DEV) up -d
	@echo "$(COLOR_SUCCESS)✅ Services rebuilt and restarted$(COLOR_RESET)"
	@echo ""
	@echo "$(COLOR_INFO)💡 View logs:$(COLOR_RESET)"
	@echo "   make dev-services-logs"

build:
	@echo "$(COLOR_INFO)🔨 Building all binaries (release mode)...$(COLOR_RESET)"
	@cargo build --release --workspace --bins
	@echo "$(COLOR_SUCCESS)✅ Build complete$(COLOR_RESET)"

test:
	@echo "$(COLOR_INFO)🔑 Generating test keys...$(COLOR_RESET)"
	@./scripts/generate_test_keys.sh
	@echo "$(COLOR_INFO)🧪 Running tests...$(COLOR_RESET)"
	@cargo test --all-targets -- --test-threads=1 || (EXIT_CODE=$$?; ./scripts/cleanup_test_keys.sh; exit $$EXIT_CODE)
	@./scripts/cleanup_test_keys.sh
	@echo "$(COLOR_SUCCESS)✅ Tests passed$(COLOR_RESET)"

# ============================================================================
# Test Infrastructure (Docker Compose)
# ============================================================================

.PHONY: test-env-up test-env-down test-env-logs test-integration test-e2e

test-env-up:
	@echo "$(COLOR_INFO)🐳 Starting test infrastructure (Postgres + Redis + Redpanda)...$(COLOR_RESET)"
	@$(COMPOSE_TEST) up -d
	@echo "$(COLOR_INFO)⏳ Waiting for services to be healthy...$(COLOR_RESET)"
	@sleep 5
	@$(COMPOSE_TEST) ps
	@echo "$(COLOR_SUCCESS)✅ Test infrastructure ready$(COLOR_RESET)"
	@echo ""
	@echo "$(COLOR_INFO)📋 Connection details:$(COLOR_RESET)"
	@echo "  PostgreSQL: postgresql://construct_test:construct_test_password@localhost:5433/construct_test"
	@echo "  Redis:      redis://localhost:6380"
	@echo "  Redpanda:   localhost:9093 (Kafka protocol)"
	@echo ""
	@echo "$(COLOR_INFO)💡 Run tests with: make test-integration$(COLOR_RESET)"

test-env-down:
	@echo "$(COLOR_INFO)🛑 Stopping test infrastructure...$(COLOR_RESET)"
	@$(COMPOSE_TEST) down -v
	@echo "$(COLOR_SUCCESS)✅ Test infrastructure stopped$(COLOR_RESET)"

test-env-logs:
	@echo "$(COLOR_INFO)📜 Test infrastructure logs:$(COLOR_RESET)"
	@$(COMPOSE_TEST) logs -f

test-integration:
	@echo "$(COLOR_INFO)🧪 Running integration tests (with Redpanda)...$(COLOR_RESET)"
	@echo "$(COLOR_INFO)⚠️  Make sure test environment is running: make test-env-up$(COLOR_RESET)"
	@./scripts/generate_test_keys.sh
	@cargo test --test protocol_compliance_test -- --nocapture || (EXIT_CODE=$$?; ./scripts/cleanup_test_keys.sh; exit $$EXIT_CODE)
	@cargo test --test e2e_crypto_test -- --nocapture || (EXIT_CODE=$$?; ./scripts/cleanup_test_keys.sh; exit $$EXIT_CODE)
	@./scripts/cleanup_test_keys.sh
	@echo "$(COLOR_SUCCESS)✅ Integration tests passed$(COLOR_RESET)"

test-e2e:
	@echo "$(COLOR_INFO)🧪 Running E2E cryptographic tests...$(COLOR_RESET)"
	@./scripts/generate_test_keys.sh
	@cargo test --test e2e_crypto_test -- --nocapture || (EXIT_CODE=$$?; ./scripts/cleanup_test_keys.sh; exit $$EXIT_CODE)
	@./scripts/cleanup_test_keys.sh
	@echo "$(COLOR_SUCCESS)✅ E2E crypto tests passed$(COLOR_RESET)"

check:
	@echo "$(COLOR_INFO)🔍 Running code checks...$(COLOR_RESET)"
	@cargo clippy --workspace -- -D warnings
	@cargo fmt --check
	@echo "$(COLOR_SUCCESS)✅ Code checks passed$(COLOR_RESET)"

fmt:
	@echo "$(COLOR_INFO)✨ Formatting code...$(COLOR_RESET)"
	@cargo fmt --all

clean:
	@echo "$(COLOR_INFO)🧹 Cleaning build artifacts...$(COLOR_RESET)"
	@cargo clean
	@echo "$(COLOR_SUCCESS)✅ Clean complete$(COLOR_RESET)"

# ============================================================================
# Deployment (Fly.io)
# ============================================================================

.PHONY: deploy deploy-gateway deploy-auth deploy-user deploy-msg deploy-notif deploy-media deploy-worker check-deploy

# Check compilation before deploying (legacy - kept for backward compatibility)
check-deploy:
	@if [ -z "$$SKIP_CHECK" ]; then \
		echo "$(COLOR_INFO)🔍 Checking code compilation...$(COLOR_RESET)"; \
		cargo check --release --workspace || \
			(echo "$(COLOR_ERROR)❌ Compilation failed!$(COLOR_RESET)" && exit 1); \
		echo "$(COLOR_SUCCESS)✓ Code compiles successfully$(COLOR_RESET)"; \
	fi

# ============================================================================
# Pre-deployment Validation (new - comprehensive checks)
# ============================================================================

.PHONY: pre-deploy-check-gateway pre-deploy-check-auth pre-deploy-check-user pre-deploy-check-msg pre-deploy-check-notif pre-deploy-check-media pre-deploy-check-worker
.PHONY: validate-secrets-gateway validate-secrets-auth validate-secrets-user validate-secrets-msg validate-secrets-notif validate-secrets-media validate-secrets-worker

# Pre-deployment checks (compilation + secrets)
pre-deploy-check-gateway:
	@bash scripts/pre-deploy-check.sh api-gateway

pre-deploy-check-auth:
	@bash scripts/pre-deploy-check.sh auth-service

pre-deploy-check-user:
	@bash scripts/pre-deploy-check.sh user-service

pre-deploy-check-msg:
	@bash scripts/pre-deploy-check.sh messaging-service

pre-deploy-check-notif:
	@bash scripts/pre-deploy-check.sh notification-service

pre-deploy-check-media:
	@bash scripts/pre-deploy-check.sh media-service

pre-deploy-check-worker:
	@bash scripts/pre-deploy-check.sh worker

# Secrets validation only (without compilation check)
validate-secrets-gateway:
	@bash scripts/validate-service-secrets.sh api-gateway

validate-secrets-auth:
	@bash scripts/validate-service-secrets.sh auth-service

validate-secrets-user:
	@bash scripts/validate-service-secrets.sh user-service

validate-secrets-msg:
	@bash scripts/validate-service-secrets.sh messaging-service

validate-secrets-notif:
	@bash scripts/validate-service-secrets.sh notification-service

validate-secrets-media:
	@bash scripts/validate-service-secrets.sh media-service

validate-secrets-worker:
	@bash scripts/validate-service-secrets.sh worker

# Deploy all microservices
deploy:
	@echo "$(COLOR_INFO)🚀 Deploying all microservices...$(COLOR_RESET)"
	@echo ""
	@echo "1/7 Deploying API Gateway..."
	@$(MAKE) deploy-gateway
	@echo ""
	@echo "2/7 Deploying Auth Service..."
	@$(MAKE) deploy-auth
	@echo ""
	@echo "3/7 Deploying User Service..."
	@$(MAKE) deploy-user
	@echo ""
	@echo "4/7 Deploying Messaging Service (Phase 4.5: END_SESSION support)..."
	@$(MAKE) deploy-msg
	@echo ""
	@echo "5/7 Deploying Notification Service..."
	@$(MAKE) deploy-notif
	@echo ""
	@echo "6/7 Deploying Media Service..."
	@$(MAKE) deploy-media
	@echo ""
	@echo "7/7 Deploying Delivery Worker..."
	@$(MAKE) deploy-worker
	@echo ""
	@echo "$(COLOR_SUCCESS)✅ All microservices deployed!$(COLOR_RESET)"
	@echo ""
	@echo "$(COLOR_INFO)💡 Next steps:$(COLOR_RESET)"
	@echo "   make status      # Check deployment status"
	@echo "   make logs-msg    # View messaging service logs"

# Deploy individual services (with comprehensive pre-deploy checks)
deploy-gateway: pre-deploy-check-gateway
	@echo "$(COLOR_INFO)🚀 Deploying API Gateway...$(COLOR_RESET)"
	@fly apps create $(APP_GATEWAY) 2>/dev/null || true
	@fly deploy --config ops/fly.api-gateway.toml --dockerfile ops/Dockerfile --app $(APP_GATEWAY)
	@echo "$(COLOR_SUCCESS)✅ Gateway deployed$(COLOR_RESET)"

deploy-auth: pre-deploy-check-auth
	@echo "$(COLOR_INFO)🚀 Deploying Auth Service...$(COLOR_RESET)"
	@fly apps create $(APP_AUTH) 2>/dev/null || true
	@fly deploy --config ops/fly.auth-service.toml --dockerfile ops/Dockerfile --app $(APP_AUTH)
	@echo "$(COLOR_SUCCESS)✅ Auth Service deployed$(COLOR_RESET)"

deploy-user: pre-deploy-check-user
	@echo "$(COLOR_INFO)🚀 Deploying User Service...$(COLOR_RESET)"
	@fly apps create $(APP_USER) 2>/dev/null || true
	@fly deploy --config ops/fly.user-service.toml --dockerfile ops/Dockerfile --app $(APP_USER)
	@echo "$(COLOR_SUCCESS)✅ User Service deployed$(COLOR_RESET)"

deploy-msg: pre-deploy-check-msg
	@echo "$(COLOR_INFO)🚀 Deploying Messaging Service (Phase 4.5: /api/v1/control)...$(COLOR_RESET)"
	@fly apps create $(APP_MSG) 2>/dev/null || true
	@fly deploy --config ops/fly.messaging-service.toml --dockerfile ops/Dockerfile --app $(APP_MSG)
	@echo "$(COLOR_SUCCESS)✅ Messaging Service deployed$(COLOR_RESET)"

deploy-notif: pre-deploy-check-notif
	@echo "$(COLOR_INFO)🚀 Deploying Notification Service...$(COLOR_RESET)"
	@fly apps create $(APP_NOTIF) 2>/dev/null || true
	@fly deploy --config ops/fly.notification-service.toml --dockerfile ops/Dockerfile --app $(APP_NOTIF)
	@echo "$(COLOR_SUCCESS)✅ Notification Service deployed$(COLOR_RESET)"

deploy-media: pre-deploy-check-media
	@echo "$(COLOR_INFO)🚀 Deploying Media Service...$(COLOR_RESET)"
	@fly apps create $(APP_MEDIA) 2>/dev/null || true
	@fly deploy --config ops/fly.media.toml --dockerfile ops/Dockerfile --app $(APP_MEDIA)
	@echo "$(COLOR_SUCCESS)✅ Media Service deployed$(COLOR_RESET)"

deploy-worker: pre-deploy-check-worker
	@echo "$(COLOR_INFO)🚀 Deploying Delivery Worker...$(COLOR_RESET)"
	@fly apps create $(APP_WORKER) 2>/dev/null || true
	@fly deploy --config ops/fly.worker.toml --dockerfile ops/Dockerfile --app $(APP_WORKER)
	@echo "$(COLOR_SUCCESS)✅ Delivery Worker deployed$(COLOR_RESET)"

# ============================================================================
# Secrets Management
# ============================================================================

.PHONY: secrets secrets-gateway secrets-auth secrets-user secrets-msg secrets-notif secrets-media secrets-worker

secrets:
	@echo "$(COLOR_INFO)🔐 Setting secrets for all services...$(COLOR_RESET)"
	@if [ ! -f .env ]; then \
		echo "$(COLOR_ERROR)❌ Error: .env file not found$(COLOR_RESET)"; \
		exit 1; \
	fi
	@echo ""
	@$(MAKE) secrets-gateway
	@$(MAKE) secrets-auth
	@$(MAKE) secrets-user
	@$(MAKE) secrets-msg
	@$(MAKE) secrets-notif
	@$(MAKE) secrets-media
	@$(MAKE) secrets-worker
	@echo ""
	@echo "$(COLOR_SUCCESS)✅ Secrets set for all services$(COLOR_RESET)"

secrets-gateway:
	@echo "$(COLOR_INFO)🔐 Setting secrets for API Gateway...$(COLOR_RESET)"
	@bash ops/setup-fly-secrets.sh api-gateway

secrets-auth:
	@echo "$(COLOR_INFO)🔐 Setting secrets for Auth Service...$(COLOR_RESET)"
	@bash ops/setup-fly-secrets.sh auth-service

secrets-user:
	@echo "$(COLOR_INFO)🔐 Setting secrets for User Service...$(COLOR_RESET)"
	@bash ops/setup-fly-secrets.sh user-service

secrets-msg:
	@echo "$(COLOR_INFO)🔐 Setting secrets for Messaging Service...$(COLOR_RESET)"
	@bash ops/setup-fly-secrets.sh messaging-service

secrets-notif:
	@echo "$(COLOR_INFO)🔐 Setting secrets for Notification Service...$(COLOR_RESET)"
	@bash ops/setup-fly-secrets.sh notification-service

secrets-media:
	@echo "$(COLOR_INFO)🔐 Setting secrets for Media Service...$(COLOR_RESET)"
	@bash ops/setup-fly-secrets.sh media-service

secrets-worker:
	@echo "$(COLOR_INFO)🔐 Setting secrets for Delivery Worker...$(COLOR_RESET)"
	@bash ops/setup-fly-secrets.sh worker

# ============================================================================
# Monitoring
# ============================================================================

.PHONY: status logs logs-gateway logs-auth logs-user logs-msg logs-notif logs-media logs-worker

status:
	@echo "$(COLOR_INFO)📊 Checking status of all microservices...$(COLOR_RESET)"
	@echo ""
	@echo "=== API Gateway ==="
	@fly status --app $(APP_GATEWAY) 2>/dev/null || echo "$(COLOR_WARNING)⚠️  Not deployed$(COLOR_RESET)"
	@echo ""
	@echo "=== Auth Service ==="
	@fly status --app $(APP_AUTH) 2>/dev/null || echo "$(COLOR_WARNING)⚠️  Not deployed$(COLOR_RESET)"
	@echo ""
	@echo "=== User Service ==="
	@fly status --app $(APP_USER) 2>/dev/null || echo "$(COLOR_WARNING)⚠️  Not deployed$(COLOR_RESET)"
	@echo ""
	@echo "=== Messaging Service (Phase 4.5) ==="
	@fly status --app $(APP_MSG) 2>/dev/null || echo "$(COLOR_WARNING)⚠️  Not deployed$(COLOR_RESET)"
	@echo ""
	@echo "=== Notification Service ==="
	@fly status --app $(APP_NOTIF) 2>/dev/null || echo "$(COLOR_WARNING)⚠️  Not deployed$(COLOR_RESET)"
	@echo ""
	@echo "=== Media Service ==="
	@fly status --app $(APP_MEDIA) 2>/dev/null || echo "$(COLOR_WARNING)⚠️  Not deployed$(COLOR_RESET)"
	@echo ""
	@echo "=== Delivery Worker ==="
	@fly status --app $(APP_WORKER) 2>/dev/null || echo "$(COLOR_WARNING)⚠️  Not deployed$(COLOR_RESET)"

logs:
	@echo "$(COLOR_INFO)📋 Recent logs from all services (last 100 lines each)...$(COLOR_RESET)"
	@echo ""
	@echo "=== API Gateway ==="
	@fly logs --app $(APP_GATEWAY) -n 100 2>/dev/null || echo "$(COLOR_WARNING)⚠️  Not available$(COLOR_RESET)"
	@echo ""
	@echo "=== Messaging Service ==="
	@fly logs --app $(APP_MSG) -n 100 2>/dev/null || echo "$(COLOR_WARNING)⚠️  Not available$(COLOR_RESET)"
	@echo ""
	@echo "=== Delivery Worker ==="
	@fly logs --app $(APP_WORKER) -n 100 2>/dev/null || echo "$(COLOR_WARNING)⚠️  Not available$(COLOR_RESET)"

logs-gateway:
	@echo "$(COLOR_INFO)📋 Streaming API Gateway logs...$(COLOR_RESET)"
	@fly logs --app $(APP_GATEWAY)

logs-auth:
	@echo "$(COLOR_INFO)📋 Streaming Auth Service logs...$(COLOR_RESET)"
	@fly logs --app $(APP_AUTH)

logs-user:
	@echo "$(COLOR_INFO)📋 Streaming User Service logs...$(COLOR_RESET)"
	@fly logs --app $(APP_USER)

logs-msg:
	@echo "$(COLOR_INFO)📋 Streaming Messaging Service logs...$(COLOR_RESET)"
	@fly logs --app $(APP_MSG)

logs-notif:
	@echo "$(COLOR_INFO)📋 Streaming Notification Service logs...$(COLOR_RESET)"
	@fly logs --app $(APP_NOTIF)

logs-media:
	@echo "$(COLOR_INFO)📋 Streaming Media Service logs...$(COLOR_RESET)"
	@fly logs --app $(APP_MEDIA)

logs-worker:
	@echo "$(COLOR_INFO)📋 Streaming Delivery Worker logs...$(COLOR_RESET)"
	@fly logs --app $(APP_WORKER)

# ============================================================================
# Database
# ============================================================================

.PHONY: db-migrate db-dev db-dev-down

db-migrate:
	@echo "$(COLOR_INFO)🗄️  Running database migrations...$(COLOR_RESET)"
	@sqlx migrate run --source shared/migrations
	@echo "$(COLOR_SUCCESS)✅ Migrations complete$(COLOR_RESET)"

db-dev:
	@echo "$(COLOR_INFO)🗄️  Starting local PostgreSQL + Redis...$(COLOR_RESET)"
	@$(COMPOSE) up -d postgres redis
	@echo "$(COLOR_SUCCESS)✅ Databases started$(COLOR_RESET)"
	@echo "   PostgreSQL: localhost:5432"
	@echo "   Redis: localhost:6379"

db-dev-down:
	@echo "$(COLOR_INFO)🛑 Stopping local databases...$(COLOR_RESET)"
	@$(COMPOSE) stop postgres redis
	@echo "$(COLOR_SUCCESS)✅ Databases stopped$(COLOR_RESET)"

# ============================================================================
# Security & Key Management
# ============================================================================

.PHONY: gen-jwt vault-up vault-down vault-init vault-status

gen-jwt:
	@echo "$(COLOR_INFO)🔑 Generating RSA keypair for RS256 JWT...$(COLOR_RESET)"
	@if [ -f jwt-private.pem ] || [ -f jwt-public.pem ]; then \
		echo "$(COLOR_WARNING)⚠️  Keys already exist:$(COLOR_RESET)"; \
		ls -lh jwt-*.pem 2>/dev/null || true; \
		echo ""; \
		echo "Delete them first if you want to regenerate:"; \
		echo "  rm -f jwt-private.pem jwt-public.pem"; \
		exit 1; \
	fi
	@openssl genrsa -out jwt-private.pem 4096
	@openssl rsa -in jwt-private.pem -pubout -out jwt-public.pem
	@echo "$(COLOR_SUCCESS)✅ RSA keypair generated$(COLOR_RESET)"
	@echo "   Private: jwt-private.pem (4096 bits)"
	@echo "   Public:  jwt-public.pem"
	@echo ""
	@echo "$(COLOR_INFO)📝 Add to .env:$(COLOR_RESET)"
	@echo "   JWT_PRIVATE_KEY=\"\$$(cat jwt-private.pem)\""
	@echo "   JWT_PUBLIC_KEY=\"\$$(cat jwt-public.pem)\""

vault-up:
	@echo "$(COLOR_INFO)🔐 Starting Vault in dev mode...$(COLOR_RESET)"
	@if docker ps --format '{{.Names}}' | grep -q '^vault-dev$$'; then \
		echo "$(COLOR_SUCCESS)✅ Vault already running$(COLOR_RESET)"; \
	else \
		docker run -d --name vault-dev \
			-p 8200:8200 \
			-e 'VAULT_DEV_ROOT_TOKEN_ID=dev-root-token' \
			-e 'VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200' \
			vault:latest && \
		sleep 2 && \
		echo "$(COLOR_SUCCESS)✅ Vault started$(COLOR_RESET)" && \
		echo "   URL: http://127.0.0.1:8200" && \
		echo "   Token: dev-root-token"; \
	fi
	@echo ""
	@echo "$(COLOR_INFO)💡 Next: make vault-init$(COLOR_RESET)"

vault-down:
	@echo "$(COLOR_INFO)🛑 Stopping Vault...$(COLOR_RESET)"
	@docker stop vault-dev 2>/dev/null || echo "$(COLOR_WARNING)⚠️  Not running$(COLOR_RESET)"
	@docker rm vault-dev 2>/dev/null || true
	@echo "$(COLOR_SUCCESS)✅ Vault stopped$(COLOR_RESET)"

vault-status:
	@echo "$(COLOR_INFO)📊 Checking Vault status...$(COLOR_RESET)"
	@if docker ps --format '{{.Names}}' | grep -q '^vault-dev$$'; then \
		echo "$(COLOR_SUCCESS)✅ Container running$(COLOR_RESET)"; \
		VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=dev-root-token vault status 2>/dev/null && \
			echo "$(COLOR_SUCCESS)✅ Vault accessible$(COLOR_RESET)" || \
			echo "$(COLOR_ERROR)❌ Cannot connect$(COLOR_RESET)"; \
	else \
		echo "$(COLOR_WARNING)⚠️  Container not running$(COLOR_RESET)"; \
		echo "   Start with: make vault-up"; \
	fi

vault-init:
	@echo "$(COLOR_INFO)🔧 Initializing Vault with Transit keys...$(COLOR_RESET)"
	@if ! docker ps --format '{{.Names}}' | grep -q '^vault-dev$$'; then \
		echo "$(COLOR_ERROR)❌ Vault not running. Start with: make vault-up$(COLOR_RESET)"; \
		exit 1; \
	fi
	@export VAULT_ADDR=http://127.0.0.1:8200 && \
	export VAULT_TOKEN=dev-root-token && \
	vault secrets enable transit 2>/dev/null || echo "Transit already enabled" && \
	vault write transit/keys/jwt-signing type=rsa-4096 && \
	vault write transit/keys/apns-encryption type=chacha20-poly1305 && \
	vault write transit/keys/federation-signing type=ed25519 && \
	vault write transit/keys/database-encryption type=aes256-gcm96 && \
	echo "$(COLOR_SUCCESS)✅ Vault initialized with all keys$(COLOR_RESET)"

# ============================================================================
# Utility
# ============================================================================

.PHONY: version

version:
	@echo "Construct Server - Phase 4.5+"
	@echo "Features: END_SESSION protocol, modular crates, microservices"
	@cargo --version
	@rustc --version

