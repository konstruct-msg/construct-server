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

CI explicitly executes the pure `cursor --check` mode: compiling the example with
`cargo test --all-targets` alone does not run its main/allocation assertions.

This is not an end-to-end RPC, throughput forecast or VPS capacity claim: auth,
SQL, crypto, APNs, dispatch-mutex contention and full subscriber response buffers
are outside this probe. In particular, a single-thread runtime and a heap guard
are **not** OS CPU/RAM quotas. A constrained Linux/VPS load stand remains necessary
before sizing groups or tuning concurrency/retention limits.

## Service-backed sealed dispatch baseline (P2)

This separate, opt-in test uses the same allocation counters and calls the production
`dispatch_sealed_sender` with local PostgreSQL 16 and Redis 7. Run it by itself on Unix,
with `DATABASE_URL` and `REDIS_URL` pointing to disposable loopback services only:

```sh
PROFILE_LOCAL_REDIS=1 cargo test --locked --release -p messaging-service \
  --bin messaging-service --features allocation-profile profile_local_sealed_dispatch \
  -- --ignored --test-threads=1 --nocapture
```

One account has two active devices and the envelope names one. The test warms up with
8 sends per size, then measures three batches of 48 sequential sends at each size.
Each send uses a fresh synthetic but valid token under `Enforce` and a unique delivery
tag. Outside the measurement it checks reply IDs/device list, exact stored bytes,
expected user and device stream lengths, sibling exclusion and that each token was
spent. SQL uses a fresh migrated schema; Redis cleanup deletes only fixture keys,
never flushes. Discard the test services after a failed run, which may leave fixture keys.

Dispatch includes decode, token redemption, device lookup and mailbox write. It does
not include request construction, gRPC ingress/egress or the outer per-IP check, APNs,
fixture setup, readback or cleanup. CPU is process CPU (not Redis/PostgreSQL CPU); wall
includes local service waits. The requested Rust bytes are churn, not RSS. Absolute
heap includes prebuilt inputs/readback fixtures. CI runs the debug form in a separate
process for the effect checks and a coarse 16 MiB peak-delta guard, not time thresholds.

A/A at production code `67fee6f`, Apple M4 Pro/macOS arm64, Rust 1.100.0 release, local
Postgres 16 and Redis 7 in containers: ranges across three fresh test processes (nine
measured batches per size). This is a baseline, not an optimization or VPS sizing result.

| Ciphertext | Allocations/send | Requested bytes/send | Process CPU µs/send | Wall µs/send | Peak Rust heap Δ/batch |
|---|---:|---:|---:|---:|---:|
| 1 KiB | 122.02–122.08 | 31,314–31,608 | 143.6–160.6 | 875–1,048 | 13,539 B |
| 64 KiB | 122.44–122.88 | 676,423–676,607 | 199.4–204.7 | 1,150–1,242 | 400,626 B |

### Moving the owned sealed buffer (P2.1)

Same release fixture above, with baseline `6d0fb66` and the owned-buffer variant
alternated on the same local services (ABBA twice, 12 batches per size per variant).
Medians per send except for peak heap, which is the delta for a batch:

| Ciphertext | Allocations | Requested bytes | Process CPU µs | Peak Rust heap Δ |
|---|---:|---:|---:|---:|
| 1 KiB | 122.04 → 121.04 | 31,437 → 30,123 | 155.4 → 152.6 | 13,539 → 12,225 B |
| 64 KiB | 122.79 → 121.75 | 676,435 → 610,607 | 216.1 → 210.1 | 400,626 → 334,799 B |

The peak drops by 1,314 and 65,827 bytes, respectively: the size of the encoded
`SealedInner`, not just its ciphertext field. CPU ranges overlap for both sizes;
this run establishes an allocation saving, not a CPU or throughput improvement.

## MessageStream backpressure baseline (P2)

On Unix, run only this test in its own process against disposable loopback Redis:

```sh
PROFILE_LOCAL_REDIS=1 REDIS_URL=redis://127.0.0.1:6379 \
  cargo test --locked --release -p messaging-service --bin messaging-service \
  --features allocation-profile profile_local_mailbox_stream \
  -- --ignored --test-threads=1 --nocapture
```

Two independent authenticated mailboxes each hold 192 opaque 1/64 KiB payloads,
with distinct messages at equal user/device Redis IDs. The test serves the actual
MessageStream over loopback HTTP/2 (test client receive windows 16 KiB stream /
32 KiB connection, adaptive window off). Both readers drain in the control. The
slow reader stops after one frame in the second case; the test waits until the
server's unchanged response channel is full and the other reader has drained.
Then it drops the slow reader, checks stream and presence teardown, and resumes
from that one received frame. `GetPendingMessages` limits 0/1 and exact byte, ID,
order and checkpoint assertions cover the other message at the same Redis ID.
Reads must not trim either stream. No PostgreSQL or production secrets are used.
Use disposable Redis; after a failed run, isolated fixture keys may remain.

Per-frame preparation is measured from cursor encoding through response creation
and ID selection, excluding Redis reads. Send wait is time inside the channel
send; for a pending slow-reader send it is observed through cancellation. CPU and
allocation counters cover both client and server in the same test process. They
exclude preload, reconnect and cleanup; live bytes are sampled separately on
closing the second reader while the first is still open. Requested bytes are churn,
not RSS. This fixture is not a network sizing or throughput benchmark.

Release A/A: three fresh processes, Rust 1.100, macOS arm64, Redis 7 in a local
container. At 1 KiB the slow-reader queue reached 128 and closing the reader
released 646–648 kB of process-wide live Rust heap. At 64 KiB it also reached 128;
closing released 10,293,818 B in each process. With both readers draining, closing
the second released about 393 kB and 481–563 kB, respectively. In the 64 KiB
slow case the enrolled 131 frames include the blocked send: its measured channel
wait was about 14–15 ms through cancellation, while preparing those frames took
0.031–0.035 ms in total. These conditions intentionally make the queue fill; they
do not predict how often real phones fill it. Neither CPU nor total allocations
are directly comparable across cases that prepared different numbers of frames.
CI checks the observed queue, byte/ID/reconnect effects and teardown, without
time thresholds.

### Retained ciphertext by owner

The same command emits `mailbox_retention` at idle, first send (before saturation),
blocked/drained, and close. The test probes count `sealed_inner` **Vec capacities**
as frames enter/leave the real queue, wait in `send`, or remain in the decoded
page iterator. They exclude metadata, queue storage, other copies and allocator
padding. Separate process-wide live heap samples include both clients, the server
and the harness, but not Redis or the kernel.

Three fresh release processes on the same local setup gave identical component
counts at the sampled stall, with the first reader already drained:

| Ciphertext/frame | Queue (128 frames) | Pending send | Decoded page tail | Unread gRPC bytes | Total live heap released on close |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1 KiB | 131,072 B | 1,024 B | 35,840 B (35) | 32,067 B | 646,305 B |
| 64 KiB | 8,388,608 B | 65,536 B | 1,245,184 B (19) | 65,702 B | 10,293,834–10,293,983 B |

`Unread gRPC bytes` is the sum of uncompressed Protobuf lengths plus the 5-byte
gRPC prefixes for frames taken by tonic, minus those decoded by the app. It
measures logical backlog, **not HTTP/2 heap or even bytes known to have been
encoded**. At close any such bytes are abandoned; the `closed` line keeps that
count for diagnosis, not as evidence of live buffers. Do not add it to heap or
assign the unexplained release to HTTP/2. With both readers draining, each counted
stock and the backlog reached zero. When the stalled reader closed, its queue,
waiting send and page stocks all reached zero before reconnect.

For 64 KiB, the three directly counted ciphertext stocks totaled 9.25 MiB at the
stall, versus about 9.82 MiB of process-wide live heap released on close. This
locates the first place to investigate for large payloads; it does not justify a
new queue/window limit or a production retention estimate. The 1 KiB case leaves
most of the release unattributed by this payload-only accounting.

### Queue-capacity experiment: keep 128 in production

Run each arm in its own release process against exclusive disposable loopback
Redis (the test reads server-wide `INFO commandstats` for actual XREAD calls):

```sh
export PROFILE_LOCAL_REDIS=1 REDIS_URL=redis://127.0.0.1:6379
for cap in 128 128 128 128 64 64 128 128 64 64 128; do
  PROFILE_STREAM_CAPACITY="$cap" cargo test --locked --release -p messaging-service \
    --bin messaging-service --features allocation-profile profile_stream_capacity_ab \
    -- --ignored --test-threads=1 --nocapture || exit
done
```

This is 3 initial A/A processes and two ABBA blocks, four samples per arm in
ABBA. The override applies only to the two instrumented mailboxes in the test
binary. Production remains at 128 frames. Each mailbox holds 320 entries:
1 KiB, 64 KiB, or a repeated mix (6 × 1 KiB, 1 × 8 KiB, 1 × 64 KiB). The real
HTTP/2 endpoints use either tonic defaults or the narrow test windows above.
The second client drains, pauses after one frame and resumes on the same RPC,
or pauses and reconnects using the last received frame. Pause ends when the
first client has drained and the second has either filled its channel or staged
all frames (possible with default windows). This is a deliberately different
amount of read-ahead at resume but the exact same 319 frames to receive.

Local Rust 1.100/macOS arm64, Redis 7; ABBA medians (128 → 64):

| Resume case | Extra process live heap at pause (MiB) | Resume to exact last frame (ms) | Total XREADs across both clients |
| --- | ---: | ---: | ---: |
| 1 KiB, default | 1.15 → 1.15 | 0.17 → 0.17 | 17–18 → 18 |
| 1 KiB, narrow | 1.00 → 0.84 | 3.78 → 7.65 | 16 → 16 |
| 64 KiB, default | 13.80 → 7.50 | 42.85 → 108.74 | 17 → 17 |
| 64 KiB, narrow | 10.33 → 7.17 | 78.03 → 115.03 | 18 → 18 |
| Mixed, default | 3.96 → 3.76 | 0.91 → 1.92 | 18 → 16 |
| Mixed, narrow | 2.47 → 1.94 | 14.69 → 21.94 | 17 → 17 |

For 64 KiB with default windows the observed resume ranges were 37.83–54.86 vs
98.04–111.74 ms (128 A/A 36.25–41.52 ms); with narrow windows they were
77.13–79.98 vs 105.56–116.93 ms (one 128 A/A outlier at 177.99 ms). The
smaller queue leaves more work for after the client resumes. This is not a claim
of lower steady-state throughput. Both-draining wall times and CPU are noisy;
there is no consistent improvement and no claim of equivalence. For 1 KiB with
default windows the producer staged all frames, so reducing the queue did not
reduce the sampled live heap. XREAD totals include empty fallback polls. CPU is
client plus server, not Redis; live heap is relative to the pre-open snapshot,
not RSS. CI checks exact delivery, resume, reconnect, strict unary limits and
teardown, not timing. Keep 128: the memory gain on large paused frames comes with
reproducibly longer recovery in this fixture. No conclusions about VPS capacity.

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
