# API Testing Scripts

Automated tests for Construct Server passwordless authentication endpoints.

## Prerequisites

```bash
# Install HTTPie (if not installed)
brew install httpie  # macOS
# or
apt install httpie   # Linux
# or
pip install httpie   # Python

# Install jq for JSON parsing
brew install jq      # macOS
apt install jq       # Linux
```

## Quick Start

### Test Production (Fly.io)
```bash
./scripts/test-registration-flow.sh https://construct-user-service.fly.dev
```

### Test Local Development
```bash
./scripts/test-registration-flow.sh http://localhost:8080
```

## Test Scripts

### 1. `test-registration-flow.sh`
**Complete passwordless registration flow test**

Tests:
- ✅ Health check (`GET /health`)
- ✅ PoW challenge retrieval (`GET /api/v1/register/challenge`)
- ⚠️  PoW solving (simulated - requires Argon2id implementation)
- ✅ Registration endpoint structure (`POST /api/v1/register/v2`)

Example output:
```
═══════════════════════════════════════════════════════════
  Construct Server - Registration Flow Test
═══════════════════════════════════════════════════════════

Testing against: https://construct-user-service.fly.dev

[1/4] Health Check...
  ✓ Server is healthy

[2/4] Getting PoW challenge...
  ✓ Challenge received
    Challenge: e3b0c44298fc1c149afbf4c8996fb9...
    Difficulty: 8 leading zeros

[3/4] Solving PoW challenge...
  ⚠  PoW solving requires Argon2id implementation
  ⚠  Expected: ~3-7 seconds @ 38 H/s

[4/4] Testing registration endpoint structure...
  → Sending registration request...
  ⚠  Registration rejected (expected - PoW not solved)
```

## Manual Testing with HTTPie

### Get PoW Challenge
```bash
http GET https://construct-user-service.fly.dev/api/v1/register/challenge
```

Expected response:
```json
{
  "challenge": "550e8400-e29b-41d4-a716-446655440000",
  "difficulty": 8,
  "expiresAt": "2026-02-04T19:05:00Z"
}
```

### Register Device (with solved PoW)
```bash
http POST https://construct-user-service.fly.dev/api/v1/register/v2 \
  deviceId="abc123def456" \
  username="alice" \
  verifyingKey="base64encodedkey..." \
  identityPublic="base64encodedkey..." \
  signedPrekeyPublic="base64encodedkey..." \
  suiteId="Curve25519+Ed25519" \
  powSolution:='{"challenge":"550e8400...","nonce":"0000000000000000"}'
```

Expected success response:
```json
{
  "success": true,
  "deviceId": "abc123def456",
  "server": "construct-user-service.fly.dev",
  "federatedId": "abc123def456@construct-user-service.fly.dev"
}
```

## Full PoW Implementation Test

For complete end-to-end testing including PoW solving, use the Python script:

```bash
python3 scripts/test_pow_registration.py https://construct-user-service.fly.dev
```

This script:
1. Gets challenge
2. Actually solves Argon2id PoW (~3-7 seconds)
3. Completes registration with valid solution
4. Verifies account creation

## API Documentation

Full API specification: [`docs/api/DEVICE_AUTH_API_SPEC.md`](../docs/api/DEVICE_AUTH_API_SPEC.md)

## Future Test Scripts

### Planned (Priority 5):
- [ ] `test-warmup-limits.sh` - Rate limiting enforcement
- [ ] `test-recovery.sh` - Account recovery flow  
- [ ] `test-device-auth.sh` - Ed25519 signature verification
- [ ] CI/CD integration (GitHub Actions smoke tests)

## Troubleshooting

### "Connection refused"
Server is not running. Check:
```bash
flyctl status --app construct-user-service  # Production
curl http://localhost:8080/health           # Local
```

### "Invalid PoW solution"
The test script uses a simulated nonce. Use `test_pow_registration.py` for real PoW solving.

### "Challenge expired"
Challenges expire after 5 minutes. Re-run the test to get a fresh challenge.

## Contributing

When adding new endpoints, add corresponding test scripts here.
