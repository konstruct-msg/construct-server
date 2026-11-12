# Hot-path allocation probe

`hotpath_profile.rs` calls the production `MessageQueue`, `MailboxCursor::encode`,
`log_safe_id` and `hash_client_ip` helpers. It adds no instrumentation to service binaries.

Use **only local/disposable Redis**. Keys have a unique `profile:p6:<run>` mailbox
prefix and scoped dedup inputs. The probe never flushes Redis. It verifies written
entries through the real mailbox reader and checks cleanup; a failed run may leave
its own keys behind.

```sh
cargo build --release -p messaging-service --example hotpath_profile
binary="$PWD/target/release/examples/hotpath_profile"
work=$(mktemp -d) # empty working directory prevents loading the repository's .env
(
  cd "$work"
  env -i PATH="$PATH" HOME="$HOME" \
    PROFILE_LOCAL_REDIS=1 INSTANCE_DOMAIN=profile.test \
    DATABASE_URL=postgres://unused:unused@127.0.0.1/unused \
    REDIS_URL=redis://127.0.0.1:6379 LOG_HASH_SALT=profile-only-salt \
    "$binary" clone
)
rmdir "$work"
```

Modes: `clone`, `hash`, `cursor`, `mailbox`, or `all` (default). Add `--check` after the mode
to enforce deterministic allocation guards: only the holder vector allocates in
`clone`, and only one output String per call in `hash` / `cursor`. These guards are for the
optimized implementation; omit them when measuring an older baseline. Network
latency is never an assertion. Run each mode in a fresh
process for OS peak-RSS comparisons (`/usr/bin/time -l` on macOS, `-v` on Linux).
Keep environment, compiler, Redis and workload identical across revisions.

- `clone`: retain 100, 1,000 and 5,000 queue handles (like open stream readers).
  Includes the holder vector; configuration is the fixture loaded above, not a
  model of every production secret/certificate configuration.
- `hash`: 100,000 log-ID and IP-tag encodings, using public fixture inputs.
- `cursor`: 100,000 encodings of a source checkpoint; one 87-byte output allocation, no
  ciphertext, network or Redis work. The normal Display `.to_string()` path initially used
  five allocations/reallocations and requested 248 bytes; the wire encoder reserves once.
  This compares implementations of the **new** token, not new tokens against old scalar IDs.
- `mailbox`: one current-thread Tokio runtime, exactly four workers, 128 sends per
  worker, 1 KiB ciphertext and 1/3/32 destination-device copies plus the user copy.
  No task-per-recipient expansion. 32 devices is a transport stress fixture, **not
  an implemented group/channel protocol**.

Reports time, allocation/reallocation calls, cumulative requested bytes and live/
peak Rust heap, with a 64 MiB requested-heap guard for this fixture. Counters cover
runtime/network work during the sample and add overhead. They exclude allocator
metadata, native TLS buffers, kernel/socket and Redis memory; requested-byte totals
are allocation churn, not retained memory. CPU-only phases approximate CPU cost;
mailbox timings include Redis/network waits. Use external CPU/RSS/cgroup tools for
whole-process limits.

This is not an end-to-end RPC, throughput forecast or VPS capacity claim: auth,
SQL, crypto, APNs, dispatch-mutex contention and full subscriber response buffers
are outside this probe. In particular, a single-thread runtime and a heap guard
are **not** OS CPU/RAM quotas. A constrained Linux/VPS load stand remains necessary
before sizing groups or tuning concurrency/retention limits.

## P6 local measurements

macOS release build, local Redis 7 via Colima, fixture above; baseline is the P5
implementation (replayed on main as `3e10097`). Same inputs/runtime in both builds.
Decimal MB below; allocation counters include reallocations and holder/setup costs.

| Probe | Before | P6 |
| --- | ---: | ---: |
| Individual queue-clone allocations (excluding holder vector) | 22 | 0 |
| Held clone storage, including holder vector | 1,931 bytes/handle | 32 bytes/handle |
| Rust live heap at 5,000 held handles | 9.73 MB | 0.24 MB |
| OS peak RSS, fresh `clone` process | 19.66 MB | 7.54 MB |
| Log-ID allocations / requested bytes per call | 4 / 32 | 1 / 8 |
| IP-tag allocations / requested bytes per call | 9 / 80 | 1 / 16 |
| Log-ID / IP-tag CPU probe | 0.148 / 0.242 µs | 0.064 / 0.064 µs |
| Three-copy mailbox send allocations / requested bytes | ~93 / 27,991 | ~60 / 24,333 |
| 32-copy stress send allocations / requested bytes | ~419 / 160,065 | ~151 / 125,417 |

`--check` passes for clone/hash (and the subsequent cursor-fix encoder). Restoring byte-by-byte `format!` encoding still
passes functional golden vectors but fails the allocation guard (400,000 instead
of 100,000 allocations for log IDs). Queue sharing, prefix lifetime/config snapshot,
protocol bytes and real delivery have separate regression tests.

Do not generalize the held-reader RSS reduction to whole-service memory: the probe
excludes response queues and real client sockets. Mailbox process RSS changed only
slightly (~11.1 to ~10.6 MB), and network timings are noisy; there is no claimed RPC
throughput gain here. Serialized arguments and packed wire bytes still scale with
the number of destinations. P6 avoids temporary copies/reallocation churn, not the
necessary per-destination wire data.
