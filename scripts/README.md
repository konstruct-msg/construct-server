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
./scripts/rotate-secret.sh          # Rotate a single secret on the VPS
./scripts/emergency-rotate-all.sh   # Rotate all secrets (emergency use)
./scripts/check-secret-expiry.sh    # Check when secrets were last rotated
./scripts/create-secrets.sh         # Bootstrap secrets on a new VPS
```

## Observability

Prometheus, Alertmanager and Grafana bind to `127.0.0.1` on the server on purpose — none of them is
published. Reaching them means an SSH tunnel.

One-time setup (the host is never stored in this repository — it is public):

```bash
mkdir -p ~/.construct
echo 'CONSTRUCT_OBS_SSH=user@host' > ~/.construct/observability.env
```

Then:

```bash
./scripts/observability-tunnel.sh          # open all three, verify each, print URLs
./scripts/observability-tunnel.sh --open   # …and open Grafana
./scripts/observability-tunnel.sh status   # is it up, and does each service answer
./scripts/observability-tunnel.sh down     # close it
./scripts/observability-tunnel.sh --help
```

| | URL once open |
|---|---|
| Prometheus | http://127.0.0.1:9090 |
| Alertmanager | http://127.0.0.1:9093 |
| Grafana | http://127.0.0.1:3001 |

Ports are overridable with `CONSTRUCT_OBS_PROM_PORT`, `CONSTRUCT_OBS_ALERT_PORT`,
`CONSTRUCT_OBS_GRAFANA_PORT` — useful when something local already holds one.

**Read the `status` output rather than assuming.** It separates two failures that look identical
from the outside, because both return nothing to `curl`:

- `nothing listening on 9090 (tunnel down)` — the tunnel.
- `reachable but returned HTTP 503 (service, not tunnel)` — the service.

That distinction is the reason the script exists: on 2026-08-21 a hand-made tunnel died between two
queries, and the empty reply was indistinguishable from "that metric does not exist".

## Dev Setup

```bash
./scripts/dev-setup.sh   # Set up local development environment
```

## Version Management

```bash
./scripts/bump-version.sh [patch|minor|major]
```
