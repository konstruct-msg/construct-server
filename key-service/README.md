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
