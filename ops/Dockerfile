# Build stage
FROM rust:1.90-slim-bookworm AS builder

WORKDIR /app

# Build dependencies. Each one is here because something in the graph needs it:
#   build-essential   linking
#   cmake             aws-lc-sys (via aws-lc-rs → apns-h2 → construct-apns)
#   pkg-config        finding libssl
#   libssl-dev        openssl-sys (via native-tls); no `vendored` feature anywhere
#   protobuf-compiler + libprotobuf-dev
#                     shared/build.rs runs protoc, and the well-known types
#                     (/usr/include/google/protobuf/*.proto) live in the -dev package.
#                     Named rather than left to `protobuf-compiler`'s Recommends, which
#                     is how it vanished from CI on 2026-08-19.
#
# libsasl2-dev, libsasl2-modules and libcurl4-openssl-dev were removed: they were
# rdkafka's, and Kafka left the delivery path. Verified, not assumed — `cargo tree
# --all-features` for linux has zero matches for sasl, rdkafka or curl-sys.
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    pkg-config \
    libssl-dev \
    protobuf-compiler \
    libprotobuf-dev \
    && rm -rf /var/lib/apt/lists/*

# sqlx offline mode — no DATABASE_URL needed at build time
ENV SQLX_OFFLINE=true

# Copy workspace files
COPY Cargo.toml Cargo.lock ./
COPY .sqlx ./.sqlx
COPY crates ./crates
COPY shared ./shared
COPY messaging-service ./messaging-service
COPY identity-service ./identity-service
COPY gateway ./gateway
COPY media-service ./media-service
COPY key-service ./key-service
COPY group-service ./group-service
COPY signaling-service ./signaling-service
COPY veil-service ./veil-service
# Required because Cargo.toml lists masque-service as a workspace member
# (cargo fails to load the workspace if the path is missing). Not installed
# into the runtime image — deploy masque separately if needed.
COPY masque-service ./masque-service

# Build release bins for the multi-service image. Exclude masque (separate
# deploy surface; still present as a workspace member for local/dev builds).
# `--workspace` is required: cargo rejects `--exclude` without it. The root is a
# virtual manifest with no `default-members`, so `--workspace` selects the same
# set the bare `--bins` did — this only drops masque, nothing else changes.
# The commit this image was built from, baked into every binary by
# shared/build.rs. Declared immediately before the build so the layer cache is
# only invalidated by the SHA changing — which it must, or the image would not
# match the code. CI passes --build-arg GIT_SHA=${{ github.sha }}; a local
# `docker build` without it falls back to `git rev-parse` inside build.rs.
ARG GIT_SHA=""
ENV GIT_SHA=$GIT_SHA

RUN cargo build --release --workspace --bins --exclude masque-service

# Runtime stage
FROM debian:bookworm-slim

WORKDIR /app

# Runtime dependencies. libsasl2-2 went with rdkafka — nothing links against it now.
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Ensure /usr/local/bin is in PATH (where binaries are installed)
ENV PATH="/usr/local/bin:${PATH}"

# Copy all binaries from builder with execute permissions
COPY --from=builder --chmod=+x /app/target/release/gateway /usr/local/bin/gateway
COPY --from=builder --chmod=+x /app/target/release/identity-service /usr/local/bin/identity-service
COPY --from=builder --chmod=+x /app/target/release/messaging-service /usr/local/bin/messaging-service
COPY --from=builder --chmod=+x /app/target/release/media-service /usr/local/bin/media-service
COPY --from=builder --chmod=+x /app/target/release/key-service /usr/local/bin/key-service
COPY --from=builder --chmod=+x /app/target/release/group-service /usr/local/bin/group-service
COPY --from=builder --chmod=+x /app/target/release/signaling-service /usr/local/bin/signaling-service
COPY --from=builder --chmod=+x /app/target/release/veil-service /usr/local/bin/veil-service

# Copy migrations
COPY shared/migrations /app/migrations

# Create data directory for media-service (mounted as volume in production)
RUN mkdir -p /data/media

# Expose port
EXPOSE 8080

# CMD is overridden per-service in docker-compose
CMD ["/bin/sh"]
