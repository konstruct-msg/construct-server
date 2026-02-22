# Build stage
FROM rust:1.90-slim-bookworm as builder

WORKDIR /app

# Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    pkg-config \
    libssl-dev \
    libsasl2-dev \
    libsasl2-modules \
    libcurl4-openssl-dev \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace files
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY shared ./shared
COPY auth-service ./auth-service
COPY messaging-service ./messaging-service
COPY user-service ./user-service
COPY notification-service ./notification-service
COPY invite-service ./invite-service
COPY gateway ./gateway
COPY media-service ./media-service
COPY delivery-worker ./delivery-worker
COPY key-service ./key-service

# Build all binaries in release mode
RUN cargo build --release --bins

# Runtime stage
FROM debian:bookworm-slim

WORKDIR /app

# Copy Envoy from official image
COPY --from=envoyproxy/envoy:v1.37.0 /usr/local/bin/envoy /usr/local/bin/envoy

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    supervisor \
    ca-certificates \
    libssl3 \
    libsasl2-2 \
    && rm -rf /var/lib/apt/lists/*

# Ensure /usr/local/bin is in PATH (where binaries are installed)
ENV PATH="/usr/local/bin:${PATH}"

# Copy all binaries from builder with execute permissions
COPY --from=builder --chmod=+x /app/target/release/delivery-worker /usr/local/bin/delivery-worker
# Microservices binaries (Phase 2.6)
COPY --from=builder --chmod=+x /app/target/release/gateway /usr/local/bin/gateway
COPY --from=builder --chmod=+x /app/target/release/auth-service /usr/local/bin/auth-service
COPY --from=builder --chmod=+x /app/target/release/user-service /usr/local/bin/user-service
COPY --from=builder --chmod=+x /app/target/release/messaging-service /usr/local/bin/messaging-service
COPY --from=builder --chmod=+x /app/target/release/notification-service /usr/local/bin/notification-service
COPY --from=builder --chmod=+x /app/target/release/invite-service /usr/local/bin/invite-service
COPY --from=builder --chmod=+x /app/target/release/media-service /usr/local/bin/media-service
COPY --from=builder --chmod=+x /app/target/release/key-service /usr/local/bin/key-service

# Copy Envoy configuration for Fly.io (no TLS, localhost routing)
COPY ops/envoy.fly.yaml /app/envoy.yaml
COPY ops/supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Copy migrations for the main server
COPY shared/migrations /app/migrations

# Create data directory for media-service (will be mounted as volume in production)
RUN mkdir -p /data/media

# Expose port (used by all services)
EXPOSE 8080

# Default command (can be overridden in docker-compose or fly.toml)
# Each service (server, worker, gateway) uses its own process name from fly.toml
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
