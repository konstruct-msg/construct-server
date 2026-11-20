# PQ pre-key bundle allocation profile

Run alone on Unix with `DATABASE_URL` pointing to disposable loopback PostgreSQL 16:

```sh
cargo test --locked --release -p key-service --bin key-service \
  --features allocation-profile profile_local_pq_bundles \
  -- --ignored --test-threads=1 --nocapture
```

The opt-in test calls the production `get_prekey_bundle` and `get_prekey_bundles`
against a fresh migrated schema. It measures a singleton and a request for two of
three active devices, both with and without consuming classic and Kyber one-time
keys. Bundle signing and the warmed Ed25519 KT proof path run; the optional delegated
hybrid tree-head signer is not configured. Key upload, signature verification and
SQL assertions are outside the measured region. Each batch has 16 operations after
three warm-up calls per case. CPU is process CPU; wall time includes PostgreSQL waits.
The measured region excludes PostgreSQL CPU, outer gRPC, admission and Redis.
Requested Rust heap bytes are allocation churn, not RSS.

Before any ownership changes (`07407d4`), local Rust 1.100 release, Apple M4 Pro/macOS,
Postgres 16 in a local container. Medians of nine batch means across three fresh
processes; CPU range shown in parentheses. Each batch2 operation yields two bundles.

| Fetch | Consume | Allocations/op | Requested bytes/op | CPU µs/op | Wall µs/op |
|---|---|---:|---:|---:|---:|
| Single | No | 154.38 | 54,173 | 196 (181–224) | 406 |
| Single | Yes | 190.06 | 80,201 | 252 (229–288) | 691 |
| Batch2 | No | 331.12 | 106,887 | 385 (372–431) | 779 |
| Batch2 | Yes | 402.69 | 159,525 | 490 (460–524) | 1,276 |

The contract checks exact key IDs and bytes, Kyber OTPK signatures, the server
bundle signature, and the expected device set. SQL readback checks that the classic
key disappears and the Kyber key is soft-expired only when requested, while the
unselected device's keys remain active. CI runs the test in debug on its own database;
there are no runtime performance thresholds.

## Moving the one-time key buffers

Release A/B against `1f229b0`, same local services and fixture, ABBA twice in fresh
processes (12 measured batches per variant and case). Medians per fetch:

| Fetch | Consume | Allocations | Requested bytes | CPU µs |
|---|---|---:|---:|---:|
| Single | No | 154.38 → 154.38 | 54,241 → 54,243 | 202.2 → 200.9 |
| Single | Yes | 189.75 → 185.75 | 80,065 → 75,285 | 252.8 → 251.3 |
| Batch2 | No | 331.12 → 331.25 | 109,644 → 108,875 | 396.2 → 400.2 |
| Batch2 | Yes | 402.31 → 393.97 | 159,237 → 150,741 | 504.1 → 500.3 |

The consuming path no longer copies four buffers per complete device bundle:
classic public key (32 B), Kyber public key (1,568 B), Ed25519 signature (64 B) and
hybrid signature (3,373 B). That's 5,037 copied bytes per complete bundle removed
from the source path; the table measures the entire fetch, including SQL client
and KT allocation noise. CPU and wall-time ranges overlap in all cases. There is
no measured CPU or throughput win and no change to the no-consume code path.
