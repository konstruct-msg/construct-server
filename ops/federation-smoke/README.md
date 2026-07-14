# A5 — two-node federation smoke test

Validates the Epic A5 exit criterion: `alice@a → bob@b` sealed-sender delivery
across two independent island nodes, with the origin never learning the sender.

See `construct-docs/decisions/domestic-island-deployment.md` (Phase I0/I1) and
`decentralization-execution-plan.md` (A5).

## Two layers of coverage

| Layer | What it proves | Runs where |
|---|---|---|
| `crates/construct-federation/tests/s2s_sealed_sender_blind_test.rs` | S2S auth + **sender-blind** wire contract the receiver enforces (sign/verify round-trip, no sender on the wire, payload-hash integrity, spoofed-origin rejection, opaque forwarding) | `cargo test` — no infra |
| `ops/federation-smoke/run.sh` | The receiver contract against **two live nodes** (`.well-known` publication, payload-hash gate → 400, unsigned → 401 under mTLS) | two deployed nodes |
| `scripts/test-federation.py` | A **signed** `POST /federation/v1/sealed` from A's key → B (real signature + payload-hash accepted) — the receiver-accept path end to end | live node B + A's signing key |
| `ops/federation-smoke/sender-blind-check.sh` | Scripted **sender-blind assertion** on node B's logs after a real delivery | node B logs (docker) |
| Full manual run (below) | End-to-end **delivery** to bob's stream + sender-blind logs | two VPS / two docker projects |

The unit test + `run.sh` cover everything except the actual client-driven
delivery, which needs a registered recipient (PoW) and a genuine SealedInner — do
that with a client build or the CI harness below.

## 1. Stand up two island nodes

Two hosts inside the allowlisted zone (or two docker projects on one host).
Per node, follow `domestic-island-deployment.md` §Config sketch:

```bash
# host A
cp ops/island.env.example /opt/construct/.env      # set INSTANCE_DOMAIN=relay.a.local
cp ops/Caddyfile.island   ops/Caddyfile.relay      # RELAY_DOMAIN=relay.a.local, tls internal
echo "SERVER_SIGNING_KEY=$(openssl rand -base64 32)" >> /opt/construct/secrets/app.env
echo "FEDERATION_ENABLED=true"                      >> /opt/construct/secrets/app.env
docker compose -f ops/docker-compose.relay.yml --env-file /opt/construct/.env up -d
# host B: same, INSTANCE_DOMAIN=relay.b.local, distinct SERVER_SIGNING_KEY
```

Cross-pin the peer SPKI (no public CA needed for S2S):

```bash
# on host A, pin B:
FP_B=$(openssl s_client -connect relay.b.local:443 -servername relay.b.local </dev/null 2>/dev/null \
       | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -hex \
       | awk '{print $2}')
echo "FEDERATION_PINNED_CERTS=relay.b.local:$FP_B" >> /opt/construct/.env
# mirror on host B for relay.a.local, then `up -d` again.
```

## 2. Scriptable checks

```bash
NODE_A_URL=https://relay.a.local NODE_B_URL=https://relay.b.local \
  ops/federation-smoke/run.sh
# local self-signed (tls internal): add CURL_OPTS="-k"
```

## 3. Full delivery + sender-blind (manual / CI)

1. Register **bob** on node B (client or test-util passwordless flow).
2. From a client as **alice** on node A, send to `bob@relay.b.local` with sealed
   sender enabled. Node A's `dispatch_sealed_sender` forwards the opaque
   `sealed_inner` to `POST https://relay.b.local/federation/v1/sealed`.
3. **Assert delivery:** bob receives the message (or its device stream
   `delivery:offline:{bob}` gains an entry).
4. **Assert sender-blind on node B:**
   - node B logs show `Inbound sealed sender message delivered locally` with **no
     sender** field;
   - the inbound request body carried **no** `from`/`to` (only `sealedInner` +
     `payloadHash` + `serverSignature`);
   - `alice`'s UUID appears **nowhere** in node B's logs or `delivery_pending`.

   Scripted: `NODE_B_COMPOSE='-f ops/docker-compose.relay.yml -p nodeb' ALICE_UUID=<uuid>
   ops/federation-smoke/sender-blind-check.sh` asserts the delivery marker **and**
   UUID-absence automatically (exit 0 = both hold).
5. **Prove no foreign dependency:** firewall both hosts to domestic-only egress
   and repeat 2–4 — delivery must still succeed (this is the *island* property).
6. **Enforce auth:** set `FEDERATION_MTLS_REQUIRED=true` on both; unsigned S2S → 401.

## Notes

- `run.sh`'s unsigned-→401 check only passes when `FEDERATION_MTLS_REQUIRED=true`;
  otherwise it SKIPs (an unsigned request would fall through to dispatch).
- The payload-hash gate (→400) runs before signature verification, so it needs no
  key material — a cheap liveness check for the receiver.
- `scripts/test-federation.py` needs `pip install requests ed25519`; pass server A's
  **real** `SERVER_SIGNING_KEY` seed via `--signing-key` and A's domain via `--origin`,
  or B rejects the signature (an ephemeral key is a reachability probe only).

## Status (2026-07-14)

- **In-process contract — green.** `cargo test -p construct-federation --test
  s2s_sealed_sender_blind_test` passes 6/6 (sealed envelope is sender-blind on the wire,
  signature verify, payload-hash integrity, spoofed-origin rejection, byte-exact forwarding).
- **Live two-node delivery — remaining.** It is an ops step: it needs the node image
  (private registry) or two VPS. The harness above is turnkey; run `run.sh`, then a real
  `alice@a → bob@b` sealed send, then `sender-blind-check.sh`.
