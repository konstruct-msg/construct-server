# Scripts

Utility and testing scripts for Construct Server.

## Smoke Tests

Run against a locally running `docker-compose.smoke.yml` stack:

```bash
# Start the stack first
docker compose -f ops/docker-compose.smoke.yml up -d

# Run smoke tests
./scripts/smoke-test.sh
```

Optional args to override default hosts:
```
./scripts/smoke-test.sh [auth_host] [msg_host] [key_host] [gateway_host] [signaling_host]
# Defaults: localhost:50051 localhost:50052 localhost:50057 localhost:8080 localhost:50060
```

## Key Management

```bash
./scripts/generate_test_keys.sh     # Generate keys for local/CI testing
./scripts/cleanup_test_keys.sh      # Remove generated test keys
./scripts/generate_delivery_key.sh  # Generate delivery HMAC key
./scripts/rotate-secret.sh          # Rotate a single secret on the VPS
./scripts/emergency-rotate-all.sh   # Rotate all secrets (emergency use)
./scripts/check-secret-expiry.sh    # Check when secrets were last rotated
./scripts/create-secrets.sh         # Bootstrap secrets on a new VPS
```

## Dev Setup

```bash
./scripts/dev-setup.sh   # Set up local development environment
```

## Version Management

```bash
./scripts/bump-version.sh [patch|minor|major]
```
