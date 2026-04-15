import os, base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

seed = os.urandom(32)
sk = Ed25519PrivateKey.from_private_bytes(seed)
vk = sk.public_key().public_bytes_raw()

print("BUNDLE_SIGNING_KEY (secret, для env var):", base64.b64encode(seed).decode())
print("bundle_signing_key (public, для well-known):", base64.b64encode(vk).decode())
