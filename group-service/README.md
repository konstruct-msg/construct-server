# MLS send allocation profile

Run alone on Unix with `DATABASE_URL` and `REDIS_URL` pointed at disposable
loopback Postgres 16 and Redis 7:

```sh
cargo test --locked --release -p group-service --bin group-service \
  --features allocation-profile profile_local_mls_send \
  -- --ignored --test-threads=1 --nocapture
```

The test calls the production `SendGroupMessage` handler with a bearer token and
one active group member, a fresh migrated schema and a subscribed receiver on the
real in-process hub. It warms up with eight calls per size, then measures three
batches of 32 sequential sends each. Outside the measured interval it matches
stored and published ciphertext, response IDs, sequence numbers, epoch and
timestamps. A retry with the same client ID and different bytes must return and
publish the original row without a duplicate insert. Cleanup drops the fixture
schema and deletes only the fixture's rate key. Discard the test Redis after a
failed run, which may leave the key until it expires.

Includes handler auth, rate recording, SQL and publication. Excludes request
construction, outer gRPC transport and revocation layer, subscriber receipt and
readback, client encryption, and database/Redis CPU. One hub subscriber is not a
network fan-out benchmark. CPU is process CPU; wall time includes database and
Redis waits. Requested bytes are Rust heap churn, not RSS.

Release A/A from `49c0d50`, Rust 1.100, macOS arm64, PostgreSQL 16 and Redis 7 in
local containers. Medians of nine measured batches per size over three fresh
processes; CPU ranges in parentheses:

| Ciphertext | Allocations/send | Requested bytes/send | CPU µs/send | Wall µs/send |
|---|---:|---:|---:|---:|
| 1 KiB | 137.44 | 41,984 | 264.9 (231.1–336.5) | 1,708.9 |
| 64 KiB | 141.25 | 676,185 | 309.4 (269.6–376.3) | 1,765.7 |

CI runs the instrumented debug test with the same effect assertions and no CPU or
wall thresholds. Use this profile before and after removing individual copies.

## Moving the envelope into the hub

Release A/B against `3d5e05d`, ABBA twice on the same local fixture (12 measured
batches per size and variant). Medians per send, except for peak heap, which is
measured over a batch:

| Ciphertext | Allocations | Requested bytes | CPU µs | Peak Rust heap Δ |
|---|---:|---:|---:|---:|
| 1 KiB | 137.38 → 134.38 | 41,727 → 40,631 | 262.5 → 253.0 | 12,398 → 12,488 B |
| 64 KiB | 141.03 → 138.05 | 667,654 → 598,758 | 309.1 → 300.2 | 425,577 → 361,300 B |

The removed clone copied the ciphertext plus the two 36-byte IDs in this fixture.
Totals also include Redis and PostgreSQL client allocations. Both CPU and wall-time
ranges overlap, as do the 1 KiB peak-heap ranges. This establishes a reduction in
allocation churn, not a CPU, RSS or throughput improvement.
