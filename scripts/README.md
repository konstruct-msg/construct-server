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
./scripts/generate_test_keys.sh     # Generate PASETO test keys for local/CI testing
./scripts/cleanup_test_keys.sh      # Remove generated test keys
./scripts/preflight-secrets.sh      # Validate app.env (format, duplicates, slices)
./scripts/split-secrets.sh          # Write per-service slices from app.env + allowlist
./scripts/test-split-secrets.sh     # Allowlist / leak checks against a fixture
```

There is no periodic rotator. Break-glass rotation is the stealth-token runbook
in construct-docs (`deployment/stealth-token-keys-runbook.md` §6). Compose still
reads `app.env` directly; `split-secrets.sh` is preflighted now and becomes the
injection path in a follow-up.

See `ops/secrets-allowlist.ini` and construct-docs
`decisions/secrets-are-sliced-not-shared.md`.

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

## Bounded live messaging test window

`messaging-test-limit-window.py` is an **operator-only** temporary IP-cap override, not a
production capacity recommendation. Test accounts only; do not change bundle limits or use
identified sends to bypass sealed admission. Fix unnecessary directory requests first.

On the Docker host, install the script in a fresh root-owned mode-0700 directory named
`/var/lib/construct-loadtest/run-<12 hex digits>` (the parent must also be root-owned).
It discovers the running compose project/files/environment-file from container labels. It pins
the running image and refuses a dry render if **any other environment value** would change;
no environment/config render is printed or saved. It does not edit `.env` or `app.env`.

```bash
# In that private directory, on the host; deliberate root action, not a local benchmark.
python3 messaging-test-limit-window.py plan --cap 1200
python3 messaging-test-limit-window.py arm --cap 1200 --minutes 15 --acknowledge-reconnect
# End early once the bounded run finishes (also on any test failure):
python3 messaging-test-limit-window.py restore
```

The example ceiling is a **test workload budget**: at 10 logical sends/s, data + one receipt
alone would be 1200 envelopes/min, before control/chunks. Start with smaller finite runs;
this is not a measured sustainable capacity or a suggested permanent quota.

Before a cap change, the helper installs/enables a durable systemd calendar timer, `Persistent=true`
(across host reboot), whose restoration service retries Docker failure. Maximum window 15 min,
cap 31..1200; one window at a time, with a lock shared by apply/restore. A partial apply attempts
immediate restore; the timer remains the fallback. Restore uses the **then-running image** so
it cannot roll a concurrent newer deployment back to a scalar-cursor backend. Original unset
cap is restored as explicit effective `30`; a normal later deployment may unset it again.
Timer/manifest files remain as disabled audit artifacts; raw credentials are never saved there.

Both transitions force-recreate **messaging only**: clients reconnect; no dependencies, Caddy,
Redis or Postgres are restarted. Verify `construct_build_info` and successful real requests,
not just compose exit status. Monitor CPU/steal, available RAM, Redis eviction and OOM deltas;
stop traffic and restore on regression. The safety helper itself does not generate traffic.
Pure fake-Docker contracts: `python3 scripts/test-messaging-test-limit-window.py` (also in CI).

## Dev Setup

Local PostgreSQL and Redis: `docker compose -f ops/docker-compose.dev.yml up -d` (see the
root README, "Local Development").

## Version Management

```bash
./scripts/bump-version.sh [patch|minor|major]
```
