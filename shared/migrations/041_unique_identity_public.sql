-- Prevent identity key reuse across devices / users.
-- An identity_public key is derived from the device's keypair; registering the same
-- identity key twice would let an attacker link two accounts or replay a compromised key.
ALTER TABLE devices
    ADD CONSTRAINT unique_identity_public UNIQUE (identity_public);
