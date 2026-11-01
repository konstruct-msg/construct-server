# S2S signatures and replay claims

`FederatedEnvelope::canonical_bytes` is the signing authority for both the outbound
client and inbound messaging receiver. The JSON body stays unchanged.

The signed fields, in order, are `message_id`, `from`, `to`, `origin_server`,
`destination_server`, decimal Unix-seconds `timestamp`, and `payload_hash`.
In each UTF-8 field, escape `%` as `%25` and `:` as `%3A`, then join the seven
fields with ASCII `:`. Other bytes are unchanged. This is signing framing only:
do not escape the JSON field values or decode the signed representation as a URL.

For example, `id:%3A` becomes `id%3A%253A`. A literal escape sequence must remain
distinct from the character it resembles. The byte-exact vector and signature
substitution tests live in `src/signing.rs::invariant_tests`.

Signatures on fields containing neither `:` nor `%` remain byte-for-byte compatible
with previous nodes. Peers and relays using delimiter-containing fields (including
server ports and key addresses) must update their signing implementation together.
There is **no fallback** to raw concatenation: it would restore the same forgery.
`scripts/test-federation.py` uses the same escaping.

The receiver supplies its configured `INSTANCE_DOMAIN` as the signed destination;
the request cannot select another destination. Sealed requests sign empty `from`
and `to`; the regular endpoint requires both fields to be nonempty, so a sealed
signature cannot be used on that endpoint to burn its replay claim.

After hash and signature verification (and sealed base64 decoding), the receiver
claims `(origin_server, message_id)` using Redis `SET NX EX`, with a seven-day TTL.
The key is `fed:v2:msg:<hex SHA-256>`, hashing each UTF-8 field preceded by its
unsigned 64-bit big-endian byte length. Both claiming and releasing use this key.
This prevents an origin port from aliasing a prefix of a message identifier.
Legacy `fed:msg:*` keys expire naturally and are never consulted: accepting an
ambiguous key can acknowledge a message that was never delivered. On upgrade a
previously claimed request can reach dispatch again; local mailbox dedup and
sealed delivery tags still apply. This is not an exactly-once delivery guarantee.

A duplicate returns `duplicate`; a claim-store error returns HTTP 503. Failed
dispatch releases the claim so the origin can retry. Signed timestamps within
300 seconds in either direction are accepted, including the exact boundary;
the comparison uses unsigned absolute difference so all JSON `u64` values are
handled without overflow. This existing admission window is not a session cursor.

Prior art: [Matrix request authentication](https://spec.matrix.org/v1.19/server-server-api/#request-authentication)
signs structured canonical JSON including the destination and request target.
Here we retain existing normal-field signatures and JSON bodies, escape the
field boundaries, and distinguish sealed from regular requests by their signed
address fields. This change introduces no federation key or trust mechanism.

Run the receiver tests against a local data plane:

```sh
cargo test -p construct-federation
cargo test -p messaging-service federation:: -- --include-ignored --test-threads=1
```

The receiver tests inject only origin-key discovery. Real Ed25519 verification,
Redis claims, and production mailbox dispatch execute unchanged. A cuttable TCP
proxy exercises a claim-store outage while leaving the mailbox Redis available.
These tests do not replace the live two-VPS TLS/discovery test.
