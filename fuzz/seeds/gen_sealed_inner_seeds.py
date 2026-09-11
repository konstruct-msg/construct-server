#!/usr/bin/env python3
"""Seed corpus for the SealedInner fuzz targets.

libFuzzer discovers protobuf framing on its own, but slowly: most random bytes
fail the first varint and the run spends the night re-learning field 1. These
seeds hand it the shapes that matter and let it mutate from there.

The interesting sizes are not arbitrary. `open_sealed_token_bytes` slices at
32 ‖ 12 ‖ … ‖ 16, so 60 bytes is the shortest input it will not reject on
length — the seeds bracket it at 59/60/61.

Regenerate:  python3 seeds/gen_sealed_inner_seeds.py corpus/fuzz_sealed_inner
"""
import os, sys, hashlib

def varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)

def tag(field: int, wire: int) -> bytes:
    return varint((field << 3) | wire)

def ld(field: int, payload: bytes) -> bytes:     # length-delimited
    return tag(field, 2) + varint(len(payload)) + payload

def vi(field: int, value: int) -> bytes:         # varint field
    return tag(field, 0) + varint(value)

UUID = b"ffeeddc6-14f2-4d02-a66a-caf0d8dfeda8"
DEVICE = b"6f5e37ac" * 4                          # 32-char hex CryptoDeviceId

def seal(n: int) -> bytes:
    """A blob shaped like an X25519 seal: eph(32) ‖ nonce(12) ‖ ct ‖ tag(16)."""
    return bytes((i * 37 + 11) & 0xFF for i in range(n))

seeds = {}

seeds["empty"] = b""
seeds["recipient_only"] = ld(1, UUID)

# The ordinary envelope: recipient, delivery tag, payload, device.
seeds["plain"] = (
    ld(1, UUID) + ld(2, seal(32)) + ld(4, seal(256)) + ld(19, DEVICE)
)

# Paying with a Privacy Pass token (nonce 32 ‖ sealed token 32+12+32+16).
seeds["with_token"] = (
    ld(1, UUID) + ld(2, seal(32)) + ld(4, seal(128))
    + ld(16, seal(32)) + ld(17, seal(92)) + ld(18, seal(32)) + ld(19, DEVICE)
)

# Vouched by an intake credential: 16-byte tag sealed → 32+12+16+16 = 76.
seeds["with_intake"] = (
    ld(1, UUID) + ld(2, seal(32)) + ld(4, seal(128))
    + ld(19, DEVICE) + ld(20, seal(76))
)

# Both at once — the state `dispatch_sealed_sender` short-circuits.
seeds["intake_and_token"] = (
    ld(1, UUID) + ld(2, seal(32)) + ld(4, seal(64))
    + ld(16, seal(32)) + ld(17, seal(92)) + ld(20, seal(76))
)

# Boundaries of the seal opener's one length check (EPH+NONCE+TAG = 60).
for n in (0, 1, 59, 60, 61):
    seeds[f"seal_len_{n}"] = ld(1, UUID) + ld(17, seal(n)) + ld(20, seal(n))

# Wrong lengths in the fields whose length decides the branch.
seeds["nonce_31"] = ld(1, UUID) + ld(16, seal(31)) + ld(17, seal(92))
seeds["nonce_33"] = ld(1, UUID) + ld(16, seal(33)) + ld(17, seal(92))
seeds["spend_id_31"] = ld(1, UUID) + ld(18, seal(31))
seeds["spend_id_32"] = ld(1, UUID) + ld(18, seal(32))

# Empty recipient — bails before any I/O, and every field after it is dead code.
seeds["empty_recipient"] = ld(1, b"") + ld(17, seal(92))

# Deprecated fields 5/6/7 the server is told to ignore, at their enum edges.
seeds["deprecated_fields"] = ld(1, UUID) + vi(5, 27) + vi(5, 0xFFFFFFFF) + vi(6, 3) + vi(7, 0xFFFFFFFF)

# Duplicate non-repeated fields: last wins per spec. Worth pinning because two
# clients disagreeing here is a silent divergence, not a parse error.
seeds["duplicate_recipient"] = ld(1, UUID) + ld(1, b"someone-else")

# Unknown fields. SealedInner declares no submessage, so the only way to reach
# prost's recursion limit is a group-encoded unknown — which is exactly the
# nesting the pre-auth parse limits were never shown to bound.
nested = b""
for depth in range(120):
    nested = tag(9, 3) + nested + tag(9, 4)
seeds["nested_groups_120"] = ld(1, UUID) + nested

nested8 = b""
for depth in range(8):
    nested8 = tag(9, 3) + nested8 + tag(9, 4)
seeds["nested_groups_8"] = ld(1, UUID) + nested8

# Truncated length prefix: claims 4 KB, carries nothing.
seeds["truncated_length"] = tag(4, 2) + varint(4096)

# A single field that fills the 512 KB pre-auth cap other services apply.
seeds["large_payload"] = ld(1, UUID) + ld(4, seal(64 * 1024))

out_dir = sys.argv[1] if len(sys.argv) > 1 else "corpus/fuzz_sealed_inner"
os.makedirs(out_dir, exist_ok=True)
for name, data in seeds.items():
    digest = hashlib.sha256(data).hexdigest()[:16]
    with open(os.path.join(out_dir, f"{name}-{digest}"), "wb") as f:
        f.write(data)
print(f"{len(seeds)} seeds -> {out_dir}")
